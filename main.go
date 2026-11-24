package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	appVersion   = "3.0.0-rc.1"
	upstreamHost = "https://agent.teleai.com.cn"
	apiPrefix    = "/superCowork/sapi"
	chatPath     = apiPrefix + "/api/v1/chat/completions"
	authPrefix   = "superagent-auth-v1"
)

type authState struct {
	Token      string `json:"token"`
	DeviceID   string `json:"deviceId"`
	InstallID  string `json:"installId"`
	OSType     string `json:"-"`
	DeviceOS   string `json:"-"`
	ClientType string `json:"-"`
}

type encryptedAuth struct {
	Version    string `json:"version"`
	IV         string `json:"iv"`
	Tag        string `json:"tag"`
	Ciphertext string `json:"ciphertext"`
}

type contentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL *struct {
		URL string `json:"url"`
	} `json:"image_url,omitempty"`
}

type toolCall struct {
	Index    *int   `json:"index,omitempty"`
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function,omitempty"`
}

type message struct {
	Role             string          `json:"role"`
	Content          json.RawMessage `json:"content,omitempty"`
	ReasoningContent string          `json:"reasoning_content,omitempty"`
	ToolCalls        []toolCall      `json:"tool_calls,omitempty"`
	ToolCallID       string          `json:"tool_call_id,omitempty"`
	Name             string          `json:"name,omitempty"`
}

type chatRequest struct {
	responseTools      map[string]responseTool
	Model              string          `json:"model"`
	Messages           []message       `json:"messages"`
	Stream             bool            `json:"stream,omitempty"`
	MaxTokens          int             `json:"max_tokens,omitempty"`
	Temperature        *float32        `json:"temperature,omitempty"`
	Tools              json.RawMessage `json:"tools,omitempty"`
	ToolChoice         json.RawMessage `json:"tool_choice,omitempty"`
	ReasoningEffort    string          `json:"reasoning_effort,omitempty"`
	ChatTemplateKwargs json.RawMessage `json:"chat_template_kwargs,omitempty"`
	StreamOptions      json.RawMessage `json:"stream_options,omitempty"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	statePath := flag.String("auth-state", "", "encrypted auth state JSON path")
	sessionKey := flag.String("session-key", "", "local session key; prefer TELEAGENT_SESSION_KEY")
	flag.Parse()
	if err := serve(*addr, *statePath, *sessionKey); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(addr, statePath, sessionKey string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host != "127.0.0.1" && host != "localhost" {
		return errors.New("refusing non-loopback listen address")
	}
	if _, err := loadState(statePath, sessionKey); err != nil {
		return fmt.Errorf("logged-in TeleAgent auth state not found: %w", err)
	}
	if statePath == "" && sessionKey == "" && os.Getenv("TELEAGENT_AUTH_STATE_FILE") == "" && os.Getenv("TELEAGENT_SESSION_KEY") == "" && os.Getenv(webTokenFileEnv) == "" {
		startRenewal()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	registerAPI(mux, func() (authState, error) { return loadState(statePath, sessionKey) })
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "teleagent2api listening on http://%s\n", addr)
	return server.ListenAndServe()
}

func loadState(path, sessionKey string) (authState, error) {
	if path != "" || sessionKey != "" || os.Getenv("TELEAGENT_AUTH_STATE_FILE") != "" || os.Getenv("TELEAGENT_SESSION_KEY") != "" {
		state, err := loadEncryptedState(path, sessionKey)
		if err != nil {
			return authState{}, err
		}
		applyDesktopProfile(&state, "")
		return state, nil
	}
	if webTokenPath := os.Getenv(webTokenFileEnv); webTokenPath != "" {
		return loadWebTokenFile(webTokenPath)
	}
	desktop, desktopErr := loadDesktopState()
	if desktopErr == nil {
		return desktop, nil
	}
	web, webErr := loadWebState()
	if webErr == nil {
		return web, nil
	}
	return authState{}, errors.Join(desktopErr, webErr)
}

func loadEncryptedState(path, sessionKey string) (authState, error) {
	if path == "" {
		path = os.Getenv("TELEAGENT_AUTH_STATE_FILE")
	}
	if sessionKey == "" {
		sessionKey = os.Getenv("TELEAGENT_SESSION_KEY")
	}
	if path == "" || sessionKey == "" {
		return authState{}, errors.New("missing auth input")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return authState{}, err
	}
	var enc encryptedAuth
	if err := json.Unmarshal(raw, &enc); err != nil {
		return authState{}, err
	}
	if enc.Version != "v1" {
		return authState{}, errors.New("unsupported auth version")
	}
	plain, err := decrypt(enc, sessionKey)
	if err != nil {
		return authState{}, err
	}
	var state authState
	if err := json.Unmarshal(plain, &state); err != nil {
		return authState{}, err
	}
	if state.Token == "" || state.InstallID == "" {
		return authState{}, errors.New("incomplete auth state")
	}
	return state, nil
}

type ownerTokenFile struct {
	Version        int    `json:"version"`
	EncryptedToken string `json:"encryptedToken"`
	Encrypted      bool   `json:"encrypted"`
	Scheme         string `json:"scheme"`
	EncryptedMeta  string `json:"encryptedMeta,omitempty"`
}

func decrypt(enc encryptedAuth, sessionKey string) ([]byte, error) {
	enc64 := base64.RawURLEncoding
	iv, err := enc64.DecodeString(enc.IV)
	if err != nil {
		return nil, err
	}
	tag, err := enc64.DecodeString(enc.Tag)
	if err != nil {
		return nil, err
	}
	ciphertext, err := enc64.DecodeString(enc.Ciphertext)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(sessionKey))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, append(ciphertext, tag...), nil)
}

func buildUpstreamBody(req chatRequest) ([]byte, error) {
	messages := make([]map[string]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		item := map[string]any{"role": m.Role}
		if len(m.Content) > 0 && string(m.Content) != "null" {
			content, err := normalizeContent(m.Content)
			if err != nil {
				return nil, err
			}
			item["content"] = content
		}
		if m.ReasoningContent != "" {
			item["reasoning_content"] = m.ReasoningContent
		}
		if len(m.ToolCalls) > 0 {
			item["tool_calls"] = m.ToolCalls
		}
		if m.ToolCallID != "" {
			item["tool_call_id"] = m.ToolCallID
		}
		if m.Name != "" {
			item["name"] = m.Name
		}
		messages = append(messages, item)
	}
	body := map[string]any{"model": req.Model, "messages": messages, "stream": true}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}
	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}
	if len(req.Tools) > 0 {
		body["tools"] = json.RawMessage(req.Tools)
	}
	if len(req.ToolChoice) > 0 {
		body["tool_choice"] = json.RawMessage(req.ToolChoice)
	}
	if req.ReasoningEffort != "" {
		body["reasoning_effort"] = req.ReasoningEffort
	}
	if len(req.ChatTemplateKwargs) > 0 {
		body["chat_template_kwargs"] = json.RawMessage(req.ChatTemplateKwargs)
	}
	return json.Marshal(body)
}

func normalizeContent(raw json.RawMessage) (any, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return []contentPart{{Type: "text", Text: text}}, nil
	}
	var parts []contentPart
	if err := json.Unmarshal(raw, &parts); err == nil {
		return parts, nil
	}
	return nil, errors.New("unsupported content")
}

func proxyChat(w http.ResponseWriter, r *http.Request, state authState, body []byte, stream bool) {
	resp, err := signedRequest(r, state, http.MethodPost, chatPath, body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream unavailable"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	if !stream {
		result, err := readCompletion(resp.Body, nil)
		if err != nil {
			writeAPIError(w, chatAPI, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result.chatJSON())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	scanner := newSSEScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "[DONE]" {
			fmt.Fprint(w, "data: [DONE]\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func signedRequest(r *http.Request, state authState, method, path string, body []byte) (*http.Response, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := newNonce()
	headers := sign(state, method, path, body, timestamp, nonce, appVersion)
	req, err := http.NewRequestWithContext(r.Context(), method, upstreamHost+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	if body != nil {
		req.Header.Set("Accept", "text/event-stream")
	}
	req.Header.Set("X-Timestamp", headers["X-SuperAgent-Timestamp"])
	req.Header.Set("X-Nonce", headers["X-SuperAgent-Nonce"])
	osType, deviceOS, client := state.OSType, state.DeviceOS, state.ClientType
	if osType == "" {
		osType, deviceOS, client = "Linux", "linux", "desktop"
		if runtime.GOOS == "windows" {
			osType, deviceOS, client = "Windows", "windows", "desktop"
		}
	}
	req.Header.Set("X-OS-Type", osType)
	req.Header.Set("X-Device-Os", deviceOS)
	req.Header.Set("X-Teleai-Client-Type", client)
	return http.DefaultClient.Do(req)
}

func sign(state authState, method, uri string, body []byte, timestamp, nonce, version string) map[string]string {
	bodyHash := hex.EncodeToString(sum256(body))
	payloadHash := hmacHex(jwtThirdSegment(state.Token), strings.Join([]string{authPrefix, state.Token, state.InstallID, timestamp, nonce}, "/"))
	signature := hmacHex(payloadHash, strings.Join([]string{
		authPrefix, strings.ToUpper(method), uri, timestamp, nonce, version, bodyHash,
	}, "\n"))
	headers := map[string]string{
		"X-Token":                   state.Token,
		"X-SuperAgent-Timestamp":    timestamp,
		"X-SuperAgent-Nonce":        nonce,
		"X-SuperAgent-Sign-Version": "v1",
		"X-SuperAgent-Signature":    signature,
		"X-App-Version":             version,
	}
	if state.DeviceID != "" {
		headers["X-SuperAgent-Device-Id"] = state.DeviceID
	}
	if state.InstallID != "" {
		headers["X-SuperAgent-Install-Id"] = state.InstallID
	}
	return headers
}

func jwtThirdSegment(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		return parts[2]
	}
	return token
}

func sum256(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }

func hmacHex(key, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func acceptsSSE(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func newSSEScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	return scanner
}
