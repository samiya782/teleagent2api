package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

type completionUsage struct {
	Prompt     int `json:"prompt_tokens"`
	Completion int `json:"completion_tokens"`
	Total      int `json:"total_tokens"`
}

type completion struct {
	id, model, finish string
	created           int64
	text, reasoning   strings.Builder
	tools             []toolCall
	usage             completionUsage
}

func readCompletion(r io.Reader, emit func(*completion, string)) (*completion, error) {
	result := &completion{}
	calls := map[int]toolCall{}
	scanner := newSSEScanner(r)
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "[DONE]" {
			break
		}
		var chunk struct {
			ID, Model string
			Created   int64
			Error     json.RawMessage
			Usage     *completionUsage
			Choices   []struct {
				Delta  message
				Finish string `json:"finish_reason"`
			}
		}
		if json.Unmarshal([]byte(data), &chunk) != nil || (len(chunk.Error) != 0 && string(chunk.Error) != "null") {
			return nil, errors.New("invalid or failed upstream completion")
		}
		if chunk.ID != "" {
			result.id, result.model, result.created = chunk.ID, chunk.Model, chunk.Created
		}
		if chunk.Usage != nil {
			result.usage = *chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]
		var text string
		_ = json.Unmarshal(choice.Delta.Content, &text)
		result.text.WriteString(text)
		result.reasoning.WriteString(choice.Delta.ReasoningContent)
		if choice.Finish != "" {
			result.finish = choice.Finish
		}
		for index, delta := range choice.Delta.ToolCalls {
			if delta.Index != nil {
				index = *delta.Index
			}
			call := calls[index]
			if delta.ID != "" {
				call.ID = delta.ID
			}
			if delta.Type != "" {
				call.Type = delta.Type
			}
			call.Function.Name += delta.Function.Name
			call.Function.Arguments += delta.Function.Arguments
			calls[index] = call
		}
		if emit != nil {
			emit(result, text)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if result.finish == "" {
		return nil, errors.New("upstream completion ended without a finish reason")
	}
	indices := make([]int, 0, len(calls))
	for index := range calls {
		indices = append(indices, index)
	}
	slices.Sort(indices)
	for _, index := range indices {
		call := calls[index]
		if call.ID == "" {
			call.ID = "call_" + newNonce()
		}
		if call.Type == "" {
			call.Type = "function"
		}
		result.tools = append(result.tools, call)
	}
	return result, nil
}

func (c *completion) chatJSON() fields {
	msg := fields{"role": "assistant", "content": c.text.String()}
	if c.reasoning.Len() > 0 {
		msg["reasoning_content"] = c.reasoning.String()
	}
	if len(c.tools) != 0 {
		msg["tool_calls"] = c.tools
		if c.text.Len() == 0 {
			msg["content"] = nil
		}
	}
	return fields{
		"id": c.id, "model": c.model, "object": "chat.completion", "created": c.created, "usage": c.usage,
		"choices": []fields{{"index": 0, "message": msg, "finish_reason": c.finish}},
	}
}

func proxyCompatible(w http.ResponseWriter, r *http.Request, state authState, req chatRequest, body []byte, format apiFormat) {
	resp, err := signedRequest(r, state, http.MethodPost, chatPath, body)
	if err != nil {
		writeAPIError(w, format, http.StatusBadGateway, "upstream unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeAPIError(w, format, resp.StatusCode, "upstream rejected the completion")
		return
	}
	out := newOutput(w, format, req)
	var emit func(*completion, string)
	if req.Stream {
		emit = out.delta
	}
	result, err := readCompletion(resp.Body, emit)
	if err != nil {
		if out.started {
			if format == messagesAPI {
				out.event("error", fields{"error": fields{"type": "api_error", "message": err.Error()}})
			} else {
				out.event("error", fields{"code": "upstream_error", "message": err.Error(), "param": nil})
			}
		} else {
			writeAPIError(w, format, http.StatusBadGateway, err.Error())
		}
		return
	}
	out.finish(result)
}

type compatibleOutput struct {
	customTools               map[string]bool
	w                         http.ResponseWriter
	format                    apiFormat
	model, id, messageID      string
	created                   int64
	stream, started, textOpen bool
	sequence                  int
}

func newOutput(w http.ResponseWriter, format apiFormat, req chatRequest) *compatibleOutput {
	prefix := "resp_"
	if format == messagesAPI {
		prefix = "msg_"
	}
	return &compatibleOutput{
		w: w, format: format, model: req.Model, stream: req.Stream, customTools: req.CustomTools,
		id: prefix + newNonce(), messageID: "msg_" + newNonce(), created: time.Now().Unix(),
	}
}

func (o *compatibleOutput) event(name string, payload fields) {
	payload["type"] = name
	if o.format == responsesAPI {
		payload["sequence_number"] = o.sequence
		o.sequence++
	}
	_, _ = fmt.Fprintf(o.w, "event: %s\ndata: %s\n\n", name, rawJSON(payload))
	if flusher, ok := o.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (o *compatibleOutput) start(c *completion) {
	if o.started {
		return
	}
	o.started = true
	o.w.Header().Set("Content-Type", "text/event-stream")
	o.w.Header().Set("Cache-Control", "no-cache")
	if o.format == messagesAPI {
		o.event("message_start", fields{"message": o.anthropicMessage(c, []fields{}, nil, 0)})
		return
	}
	o.event("response.created", fields{"response": o.responseObject("in_progress", []fields{}, nil)})
}

func (o *compatibleOutput) delta(c *completion, text string) {
	o.start(c)
	if text == "" {
		return
	}
	if o.format == messagesAPI {
		if !o.textOpen {
			o.event("content_block_start", fields{"index": 0, "content_block": fields{"type": "text", "text": ""}})
		}
		o.event("content_block_delta", fields{"index": 0, "delta": fields{"type": "text_delta", "text": text}})
	} else {
		if !o.textOpen {
			o.event("response.output_item.added", fields{"output_index": 0, "item": o.responseMessage("in_progress", []fields{})})
			o.event("response.content_part.added", fields{"item_id": o.messageID, "output_index": 0, "content_index": 0, "part": outputText("")})
		}
		o.event("response.output_text.delta", fields{"item_id": o.messageID, "output_index": 0, "content_index": 0, "delta": text})
	}
	o.textOpen = true
}

func (o *compatibleOutput) finish(c *completion) {
	if o.stream {
		o.start(c)
	}
	if o.format == messagesAPI {
		o.finishMessages(c)
	} else {
		o.finishResponses(c)
	}
}

func (o *compatibleOutput) anthropicMessage(c *completion, content []fields, stop any, outputTokens int) fields {
	return fields{
		"id": o.id, "type": "message", "role": "assistant", "model": o.model, "content": content,
		"stop_reason": stop, "stop_sequence": nil,
		"usage": fields{"input_tokens": c.usage.Prompt, "output_tokens": outputTokens},
	}
}

func (o *compatibleOutput) finishMessages(c *completion) {
	stop := "end_turn"
	switch {
	case c.finish == "length":
		stop = "max_tokens"
	case len(c.tools) > 0:
		stop = "tool_use"
	}
	content := []fields{}
	if c.text.Len() > 0 {
		content = append(content, fields{"type": "text", "text": c.text.String()})
	}
	if o.stream && o.textOpen {
		o.event("content_block_stop", fields{"index": 0})
	}
	for _, call := range c.tools {
		input := json.RawMessage(call.Function.Arguments)
		if !json.Valid(input) || !strings.HasPrefix(strings.TrimSpace(string(input)), "{") {
			if o.stream {
				o.event("error", fields{"error": fields{"type": "api_error", "message": "upstream returned invalid tool arguments"}})
			} else {
				writeAPIError(o.w, messagesAPI, http.StatusBadGateway, "upstream returned invalid tool arguments")
			}
			return
		}
		block := fields{"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": input}
		index := len(content)
		content = append(content, block)
		if o.stream {
			o.event("content_block_start", fields{"index": index, "content_block": fields{
				"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": fields{},
			}})
			o.event("content_block_delta", fields{"index": index, "delta": fields{"type": "input_json_delta", "partial_json": string(input)}})
			o.event("content_block_stop", fields{"index": index})
		}
	}
	if !o.stream {
		writeJSON(o.w, http.StatusOK, o.anthropicMessage(c, content, stop, c.usage.Completion))
		return
	}
	o.event("message_delta", fields{"delta": fields{"stop_reason": stop, "stop_sequence": nil},
		"usage": fields{"input_tokens": c.usage.Prompt, "output_tokens": c.usage.Completion}})
	o.event("message_stop", fields{})
}

func outputText(text string) fields {
	return fields{"type": "output_text", "text": text, "annotations": []any{}, "logprobs": []any{}}
}

func (o *compatibleOutput) responseMessage(status string, content []fields) fields {
	return fields{"type": "message", "id": o.messageID, "role": "assistant", "status": status, "content": content}
}

func (o *compatibleOutput) responseObject(status string, output []fields, usage any) fields {
	var incomplete any
	if status == "incomplete" {
		incomplete = fields{"reason": "max_output_tokens"}
	}
	return fields{
		"id": o.id, "object": "response", "created_at": o.created, "model": o.model, "status": status,
		"output": output, "usage": usage, "error": nil, "incomplete_details": incomplete,
	}
}

func (o *compatibleOutput) finishResponses(c *completion) {
	status := "completed"
	if c.finish == "length" {
		status = "incomplete"
	}
	output := []fields{}
	if c.text.Len() > 0 {
		part := outputText(c.text.String())
		item := o.responseMessage(status, []fields{part})
		output = append(output, item)
		if o.stream {
			o.event("response.output_text.done", fields{"item_id": o.messageID, "output_index": 0, "content_index": 0, "text": c.text.String()})
			o.event("response.content_part.done", fields{"item_id": o.messageID, "output_index": 0, "content_index": 0, "part": part})
			o.event("response.output_item.done", fields{"output_index": 0, "item": item})
		}
	}
	for _, call := range c.tools {
		index := len(output)
		id, kind := "fc_"+newNonce(), "function_call"
		value, field, event := call.Function.Arguments, "arguments", "response.function_call_arguments"
		if o.customTools[call.Function.Name] {
			var args struct{ Input *string }
			if json.Unmarshal([]byte(value), &args) != nil || args.Input == nil {
				const detail = "upstream returned invalid custom tool input"
				if o.stream {
					o.event("error", fields{"code": "upstream_error", "message": detail, "param": nil})
				} else {
					writeAPIError(o.w, responsesAPI, http.StatusBadGateway, detail)
				}
				return
			}
			id, kind = "ctc_"+newNonce(), "custom_tool_call"
			value, field, event = *args.Input, "input", "response.custom_tool_call_input"
		}
		item := func(value, status string) fields {
			return fields{"type": kind, "id": id, "call_id": call.ID, "name": call.Function.Name, field: value, "status": status}
		}
		done := item(value, status)
		output = append(output, done)
		if o.stream {
			o.event("response.output_item.added", fields{"output_index": index, "item": item("", "in_progress")})
			o.event(event+".delta", fields{"output_index": index, "item_id": id, "delta": value})
			o.event(event+".done", fields{"output_index": index, "item_id": id, "name": call.Function.Name, field: value})
			o.event("response.output_item.done", fields{"output_index": index, "item": done})
		}
	}
	response := o.responseObject(status, output, fields{
		"input_tokens": c.usage.Prompt, "output_tokens": c.usage.Completion, "total_tokens": c.usage.Total,
		"input_tokens_details": fields{"cached_tokens": 0}, "output_tokens_details": fields{"reasoning_tokens": 0},
	})
	if o.stream {
		o.event("response."+status, fields{"response": response})
		return
	}
	writeJSON(o.w, http.StatusOK, response)
}
