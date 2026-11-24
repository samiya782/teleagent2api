package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToolHistoryConversion(t *testing.T) {
	tests := []struct {
		name   string
		format apiFormat
		body   string
	}{
		{"messages", messagesAPI, `{"model":"chat-pro","system":[{"type":"text","text":"sys"}],"messages":[
			{"role":"user","content":"request"},
			{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"echo","input":{"text":"hello"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":"hello"},{"type":"text","text":"continue"}]}
		],"tools":[{"name":"echo","input_schema":{"type":"object","properties":{"text":{"type":"string"}}}}],"tool_choice":{"type":"tool","name":"echo"}}`},
		{"responses", responsesAPI, `{"model":"chat-pro","instructions":"sys","input":[
			{"role":"user","content":[{"type":"input_text","text":"request"}]},
			{"type":"function_call","id":"fc_1","call_id":"call_1","name":"echo","arguments":"{\"text\":\"hello\"}"},
			{"type":"function_call_output","call_id":"call_1","output":"hello"},
			{"role":"user","content":"continue"}
		],"tools":[{"type":"function","name":"echo","parameters":{"type":"object","properties":{"text":{"type":"string"}}}}],"tool_choice":{"type":"function","name":"echo"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := parseAPIRequest([]byte(tt.body), tt.format)
			if err != nil {
				t.Fatal(err)
			}
			if len(req.Messages) != 5 {
				t.Fatalf("got %d messages", len(req.Messages))
			}
			assistant, result := req.Messages[2], req.Messages[3]
			if assistant.Role != "assistant" || len(assistant.ToolCalls) != 1 ||
				assistant.ToolCalls[0].ID != "call_1" || assistant.ToolCalls[0].Function.Arguments != `{"text":"hello"}` ||
				result.Role != "tool" || result.ToolCallID != "call_1" || string(result.Content) != `"hello"` {
				t.Fatalf("tool call and result were not preserved: %+v %+v", assistant, result)
			}
			if !strings.Contains(string(req.Tools), `"parameters":{"type":"object"`) ||
				string(req.ToolChoice) != `{"function":{"name":"echo"},"type":"function"}` {
				t.Fatalf("unexpected tools or choice: %s %s", req.Tools, req.ToolChoice)
			}
		})
	}
}

func TestStreamInterleavedCalls(t *testing.T) {
	const upstream = `data: {"id":"upstream","model":"chat-pro","choices":[{"delta":{"content":"checking"}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"echo","arguments":"{\"text\":"}},{"index":1,"id":"call_2","function":{"name":"second","arguments":"{}"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"hello\"}"}}]},"finish_reason":"tool_calls"}]}

data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}

data: [DONE]
`
	for _, format := range []apiFormat{messagesAPI, responsesAPI} {
		w := httptest.NewRecorder()
		out := newOutput(w, format, chatRequest{Model: "chat-pro", Stream: true})
		result, err := readCompletion(strings.NewReader(upstream), out.delta)
		if err != nil {
			t.Fatal(err)
		}
		out.finish(result)
		body := w.Body.String()
		if !strings.Contains(body, `"call_1"`) || !strings.Contains(body, `"call_2"`) ||
			!strings.Contains(body, `{\"text\":\"hello\"}`) || !strings.Contains(body, `"output_tokens":5`) {
			t.Fatalf("missing calls or usage: %s", body)
		}
		end := "event: response.completed"
		if format == messagesAPI {
			end = "event: message_stop"
		}
		if !strings.Contains(body, end) {
			t.Fatalf("missing %s", end)
		}
	}
}

func TestCountTokensAndInvalidResponsesHistory(t *testing.T) {
	mux := http.NewServeMux()
	registerAPI(mux, func() (authState, error) {
		t.Fatal("request contacted upstream")
		return authState{}, nil
	})
	req := httptest.NewRequest("POST", "/v1/messages/count_tokens", strings.NewReader(`{"model":"chat-pro","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var count struct {
		Tokens int `json:"input_tokens"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &count); w.Code != http.StatusOK || err != nil || count.Tokens == 0 {
		t.Fatalf("invalid token count: %d %s", w.Code, w.Body)
	}

	req = httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"model":"chat-pro","previous_response_id":"resp_1","input":"hi"}`))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid status for unsupported history: %d %s", w.Code, w.Body)
	}
}

func TestTruncatedCompletion(t *testing.T) {
	_, err := readCompletion(strings.NewReader(`data: {"choices":[{"delta":{"content":"partial"}}]}`), nil)
	if err == nil {
		t.Fatal("truncated upstream stream reported success")
	}
}

func TestResponsesNamespacedToolRoundTrip(t *testing.T) {
	const namespace = "mcp__a_very_long_namespace_with_punctuation.example"
	const input = `{"model":"chat-pro","input":"read the fixture","tools":[
		{"type":"function","name":"read_fixture"},
		{"type":"namespace","name":"mcp__other","tools":[{"type":"function","name":"read_fixture"}]},
		{"type":"namespace","name":"mcp__a_very_long_namespace_with_punctuation.example","tools":[
			{"type":"function","name":"read_fixture","parameters":{"type":"object"}}
		]}
	],"tool_choice":{"type":"function","namespace":"mcp__a_very_long_namespace_with_punctuation.example","name":"read_fixture"}}`
	req, err := parseAPIRequest([]byte(input), responsesAPI)
	if err != nil {
		t.Fatal(err)
	}
	var tools []struct{ Function struct{ Name string } }
	if err := json.Unmarshal(req.Tools, &tools); err != nil || len(tools) != 3 {
		t.Fatalf("tools were dropped: %s (%v)", req.Tools, err)
	}
	plain, other, namespaced := tools[0].Function.Name, tools[1].Function.Name, tools[2].Function.Name
	if plain != "read_fixture" || namespaced == plain || namespaced == other || len(namespaced) > 64 ||
		toolNameCharacters.MatchString(namespaced) || !strings.Contains(string(req.ToolChoice), namespaced) {
		t.Fatalf("tool names or choice incorrectly converted: %s %s", req.Tools, req.ToolChoice)
	}

	result := &completion{finish: "tool_calls", tools: []toolCall{makeCall("call_1", namespaced, `{}`)}}
	w := httptest.NewRecorder()
	newOutput(w, responsesAPI, req).finish(result)
	var response struct{ Output []wireItem }
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Output) != 1 {
		t.Fatalf("invalid tool response: %s", w.Body)
	}
	call := response.Output[0]
	if call.Name != "read_fixture" || call.Namespace != namespace || call.CallID != "call_1" {
		t.Fatalf("tool identity lost: %+v", call)
	}

	// Replay can omit a tool definition after that tool has been called.
	replay := fields{"model": "chat-pro", "input": []any{
		fields{"type": "function_call", "namespace": call.Namespace, "name": call.Name, "call_id": call.CallID, "arguments": call.Arguments},
		fields{"type": "function_call_output", "call_id": call.CallID, "output": "fixture"},
	}}
	req, err = parseAPIRequest(rawJSON(replay), responsesAPI)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Messages) != 2 || req.Messages[0].ToolCalls[0].Function.Name != namespaced || req.Messages[1].ToolCallID != call.CallID {
		t.Fatalf("unexpected replay history: %+v", req.Messages)
	}
}

func TestResponsesNamespacedCustomToolStream(t *testing.T) {
	req, err := parseAPIRequest([]byte(`{"model":"chat-pro","stream":true,"input":"read","tools":[
		{"type":"namespace","name":"local","tools":[{"type":"custom","name":"read"}]}
	]}`), responsesAPI)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	newOutput(w, responsesAPI, req).finish(&completion{
		finish: "tool_calls",
		tools:  []toolCall{makeCall("call_2", upstreamToolName("local", "read"), `{"input":"fixture"}`)},
	})
	for _, want := range []string{`"type":"custom_tool_call"`, `"name":"read"`, `"namespace":"local"`,
		`"input":"fixture"`, "event: response.custom_tool_call_input.done", "event: response.completed"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("stream missing %s: %s", want, w.Body)
		}
	}
}
