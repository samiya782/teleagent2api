package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const anthropicModelPrefix = "teleagent-anthropic/"

type apiFormat int

const (
	chatAPI apiFormat = iota
	messagesAPI
	responsesAPI
)

func registerAPI(mux *http.ServeMux, load func() (authState, error)) {
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		state, err := load()
		if err != nil {
			writeAPIError(w, chatAPI, http.StatusUnauthorized, "auth state unavailable")
			return
		}
		serveModels(w, r, state)
	})
	for path, format := range map[string]apiFormat{
		"/v1/chat/completions": chatAPI, "/v1/messages": messagesAPI,
		"/v1/messages/count_tokens": messagesAPI, "/v1/responses": responsesAPI,
	} {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
			if err != nil {
				writeAPIError(w, format, http.StatusBadRequest, "invalid body or body exceeds 8 MiB")
				return
			}
			req, err := parseAPIRequest(body, format)
			if err != nil {
				writeAPIError(w, format, http.StatusBadRequest, err.Error())
				return
			}
			upstreamReq := req
			if format == messagesAPI {
				upstreamReq.Model = strings.TrimPrefix(req.Model, anthropicModelPrefix)
				if upstreamReq.Model == "" {
					writeAPIError(w, format, http.StatusBadRequest, "model is required")
					return
				}
			}
			upstream, err := buildUpstreamBody(upstreamReq)
			if err != nil {
				writeAPIError(w, format, http.StatusBadRequest, "invalid messages")
				return
			}
			if path == "/v1/messages/count_tokens" {
				writeJSON(w, http.StatusOK, fields{"input_tokens": (len(upstream) + 3) / 4})
				return
			}
			state, err := load()
			if err != nil {
				writeAPIError(w, format, http.StatusUnauthorized, "auth state unavailable")
				return
			}
			if format == chatAPI {
				proxyChat(w, r, state, upstream, req.Stream || acceptsSSE(r))
				return
			}
			proxyCompatible(w, r, state, req, upstream, format)
		})
	}
}

type fields = map[string]any

func writeAPIError(w http.ResponseWriter, format apiFormat, status int, detail string) {
	typ := "api_error"
	switch status {
	case http.StatusBadRequest:
		typ = "invalid_request_error"
	case http.StatusUnauthorized:
		typ = "authentication_error"
	case http.StatusTooManyRequests:
		typ = "rate_limit_error"
	}
	payload := fields{"error": fields{"type": typ, "message": detail}}
	if format == messagesAPI {
		payload["type"] = "error"
	}
	writeJSON(w, status, payload)
}

func serveModels(w http.ResponseWriter, r *http.Request, state authState) {
	resp, err := signedRequest(r, state, http.MethodGet, apiPrefix+"/api/v1/model-options?language=zh-CN", nil)
	if err != nil {
		writeAPIError(w, chatAPI, http.StatusBadGateway, "model directory unavailable")
		return
	}
	defer resp.Body.Close()
	var catalog struct {
		Code int
		Data struct {
			Models []struct {
				Model       string
				DisplayName string `json:"display_name"`
				Description string
			}
		}
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&catalog) != nil || catalog.Code != 0 || catalog.Data.Models == nil {
		writeAPIError(w, chatAPI, http.StatusBadGateway, "model directory unavailable")
		return
	}
	anthropic := r.Header.Get("anthropic-version") != "" || r.Header.Get("x-api-key") != ""
	codex := r.URL.Query().Get("format") == "codex"
	models := make([]fields, 0, len(catalog.Data.Models))
	for _, model := range catalog.Data.Models {
		if model.Model == "" {
			continue
		}
		item := fields{"id": model.Model, "object": "model", "created": 0, "owned_by": "teleagent"}
		switch {
		case codex:
			item = codexModel(model.Model, model.DisplayName, len(models))
		case anthropic:
			// Claude Code discovers only IDs containing "claude" or "anthropic".
			item = fields{
				"id": anthropicModelPrefix + model.Model, "type": "model",
				"display_name": model.Model, "description": model.Description,
				"created_at": "1970-01-01T00:00:00Z",
			}
		}
		models = append(models, item)
	}
	if codex {
		writeJSON(w, http.StatusOK, fields{"models": models})
		return
	}
	if anthropic {
		page := fields{"data": models, "has_more": false, "first_id": nil, "last_id": nil}
		if len(models) > 0 {
			page["first_id"], page["last_id"] = models[0]["id"], models[len(models)-1]["id"]
		}
		writeJSON(w, http.StatusOK, page)
		return
	}
	writeJSON(w, http.StatusOK, fields{"object": "list", "data": models})
}

// Codex's local model catalog uses a different schema than OpenAI's models list.
func codexModel(id, name string, priority int) fields {
	if name == "" {
		name = id
	}
	return fields{
		"slug": id, "display_name": name, "description": id, "priority": priority,
		"visibility": "list", "supported_in_api": true, "supported_reasoning_levels": []any{},
		"shell_type": "shell_command", "tool_mode": "function",
		"truncation_policy": fields{"mode": "tokens", "limit": 10000},
		"base_instructions": "You are a coding assistant.", "input_modalities": []string{"text"},
		"support_verbosity": false, "supports_reasoning_summaries": false,
		"supports_reasoning_effort_updates": false, "supports_search_tool": false,
		"experimental_supported_tools": []any{},
	}
}

func rawJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

type wireItem struct {
	Type, Role, Name, Text, Arguments string
	ID                                string `json:"id"`
	CallID                            string `json:"call_id"`
	ToolUseID                         string `json:"tool_use_id"`
	URL                               string `json:"image_url"`
	Content, Input, Output, Source    json.RawMessage
}

type wireTool struct {
	Type, Name, Description string
	Parameters              json.RawMessage
	InputSchema             json.RawMessage `json:"input_schema"`
}

func makeCall(id, name, arguments string) toolCall {
	call := toolCall{ID: id, Type: "function"}
	call.Function.Name, call.Function.Arguments = name, arguments
	return call
}

func decodeParts(raw json.RawMessage) ([]wireItem, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return []wireItem{{Type: "text", Text: text}}, nil
	}
	var parts []wireItem
	err := json.Unmarshal(raw, &parts)
	return parts, err
}

func textMessage(role, text string) message {
	return message{Role: role, Content: rawJSON(text)}
}

func parseAPIRequest(body []byte, format apiFormat) (chatRequest, error) {
	var req chatRequest
	if format == chatAPI {
		if err := json.Unmarshal(body, &req); err != nil || req.Model == "" || len(req.Messages) == 0 {
			return req, fmt.Errorf("model and messages are required")
		}
		return req, nil
	}
	var wire struct {
		Model, Instructions string
		Stream              bool
		MaxTokens           int    `json:"max_tokens"`
		MaxOutputTokens     int    `json:"max_output_tokens"`
		PreviousResponseID  string `json:"previous_response_id"`
		Messages            []wireItem
		System, Input       json.RawMessage
		Tools               []wireTool
		ToolChoice          json.RawMessage `json:"tool_choice"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return req, fmt.Errorf("invalid request: %w", err)
	}
	req.Model, req.Stream = wire.Model, wire.Stream
	if req.Model == "" {
		return req, fmt.Errorf("model is required")
	}
	if wire.PreviousResponseID != "" {
		return req, fmt.Errorf("send conversation history in input instead of previous_response_id")
	}
	if format == messagesAPI {
		req.MaxTokens = wire.MaxTokens
		if len(wire.Messages) == 0 {
			return req, fmt.Errorf("messages are required")
		}
		if len(wire.System) > 0 {
			if err := appendWireMessage(&req, "system", wire.System); err != nil {
				return req, err
			}
		}
		for _, item := range wire.Messages {
			if err := appendWireMessage(&req, item.Role, item.Content); err != nil {
				return req, err
			}
		}
	} else {
		req.MaxTokens = wire.MaxOutputTokens
		if wire.Instructions != "" {
			req.Messages = append(req.Messages, textMessage("system", wire.Instructions))
		}
		if err := appendResponsesInput(&req, wire.Input); err != nil {
			return req, err
		}
	}
	if len(req.Messages) == 0 {
		return req, fmt.Errorf("messages must contain text, images, or tool data")
	}
	req.Tools, req.ToolChoice, req.CustomTools = convertTools(wire.Tools, wire.ToolChoice)
	return req, nil
}

func convertTools(input []wireTool, rawChoice json.RawMessage) (json.RawMessage, json.RawMessage, map[string]bool) {
	var tools []fields
	custom := make(map[string]bool)
	for _, tool := range input {
		// Client-hosted function tools are executed by the client.
		if tool.Name == "" || (tool.Type != "" && tool.Type != "function" && tool.Type != "custom" && !strings.HasPrefix(tool.Type, "custom_")) {
			continue
		}
		schema := tool.Parameters
		if tool.Type == "custom" {
			custom[tool.Name] = true
			schema = rawJSON(fields{
				"type": "object", "required": []string{"input"},
				"properties": fields{"input": fields{"type": "string", "description": "Raw input for the tool"}},
			})
		}
		if len(schema) == 0 {
			schema = tool.InputSchema
		}
		if len(schema) == 0 {
			schema = rawJSON(fields{"type": "object", "properties": fields{}})
		}
		tools = append(tools, fields{"type": "function", "function": fields{
			"name": tool.Name, "description": tool.Description, "parameters": schema,
		}})
	}
	if len(tools) == 0 {
		return nil, nil, nil
	}
	var choice string
	if json.Unmarshal(rawChoice, &choice) == nil && choice != "" {
		return rawJSON(tools), rawChoice, custom
	}
	var object wireTool
	_ = json.Unmarshal(rawChoice, &object)
	switch object.Type {
	case "tool", "function", "custom":
		return rawJSON(tools), rawJSON(fields{"type": "function", "function": fields{"name": object.Name}}), custom
	case "any", "required":
		choice = "required"
	case "none":
		choice = "none"
	default:
		choice = "auto"
	}
	return rawJSON(tools), rawJSON(choice), custom
}

func appendWireMessage(req *chatRequest, role string, raw json.RawMessage) error {
	switch role {
	case "developer":
		role = "system"
	case "system", "user", "assistant":
	default:
		return fmt.Errorf("unsupported message role %q", role)
	}
	parts, err := decodeParts(raw)
	if err != nil {
		return err
	}
	msg := message{Role: role}
	var content []contentPart
	var results []message
	for _, part := range parts {
		switch part.Type {
		case "text", "input_text", "output_text":
			content = append(content, contentPart{Type: "text", Text: part.Text})
		case "tool_use":
			msg.ToolCalls = append(msg.ToolCalls, makeCall(part.ID, part.Name, string(part.Input)))
		case "tool_result":
			result, err := toolOutput(part.Content)
			if err != nil {
				return err
			}
			result.ToolCallID = part.ToolUseID
			results = append(results, result)
		case "image", "input_image":
			url := part.URL
			if len(part.Source) > 0 {
				var source struct {
					URL, Data string
					MediaType string `json:"media_type"`
				}
				if err := json.Unmarshal(part.Source, &source); err != nil {
					return err
				}
				url = source.URL
				if source.Data != "" {
					url = "data:" + source.MediaType + ";base64," + source.Data
				}
			}
			if url == "" {
				return fmt.Errorf("image URL or base64 data is required")
			}
			image := contentPart{Type: "image_url"}
			image.ImageURL = &struct {
				URL string `json:"url"`
			}{URL: url}
			content = append(content, image)
		case "thinking", "redacted_thinking":
			// OpenAI-compatible upstream does not use Anthropic signatures.
		default:
			return fmt.Errorf("unsupported content type %q", part.Type)
		}
	}
	req.Messages = append(req.Messages, results...)
	if len(content) > 0 {
		msg.Content = rawJSON(content)
	}
	if len(content) > 0 || len(msg.ToolCalls) > 0 {
		req.Messages = append(req.Messages, msg)
	}
	return nil
}

func toolOutput(raw json.RawMessage) (message, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return textMessage("tool", ""), nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return textMessage("tool", text), nil
	}
	temp := chatRequest{}
	if err := appendWireMessage(&temp, "user", raw); err != nil {
		return message{}, err
	}
	if len(temp.Messages) == 0 {
		return textMessage("tool", ""), nil
	}
	return message{Role: "tool", Content: temp.Messages[0].Content}, nil
}

func appendResponsesInput(req *chatRequest, raw json.RawMessage) error {
	items, err := decodeParts(raw)
	if err != nil {
		return err
	}
	for _, item := range items {
		switch item.Type {
		case "text":
			req.Messages = append(req.Messages, textMessage("user", item.Text))
		case "", "message":
			if err := appendWireMessage(req, item.Role, item.Content); err != nil {
				return err
			}
		case "function_call", "custom_tool_call":
			args := item.Arguments
			if item.Type == "custom_tool_call" {
				var input string
				if err := json.Unmarshal(item.Input, &input); err != nil {
					return fmt.Errorf("custom tool input must be a string")
				}
				args = string(rawJSON(fields{"input": input}))
			}
			n := len(req.Messages)
			if n == 0 || req.Messages[n-1].Role != "assistant" {
				req.Messages = append(req.Messages, message{Role: "assistant"})
				n++
			}
			req.Messages[n-1].ToolCalls = append(req.Messages[n-1].ToolCalls, makeCall(item.CallID, item.Name, args))
		case "function_call_output", "custom_tool_call_output":
			result, err := toolOutput(item.Output)
			if err != nil {
				return err
			}
			result.ToolCallID = item.CallID
			req.Messages = append(req.Messages, result)
		case "reasoning":
			// Codex can replay reasoning items alongside the usable message history.
		default:
			return fmt.Errorf("unsupported input type %q", item.Type)
		}
	}
	if len(items) == 0 || len(req.Messages) == 0 {
		return fmt.Errorf("input is required")
	}
	return nil
}
