package main

import (
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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	appVersion = "3.0.0-rc.1"
	upstreamHost = "https://agent.teleai.com.cn"
	apiPrefix = "/superCowork/sapi"
	chatPath = apiPrefix + "/api/v1/chat/completions"
	authPrefix = "superagent-auth-v1"
)

type authState struct {
	Token     string `json:"token"`
	DeviceID  string `json:"deviceId"`
	InstallID string `json:"installId"`
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
	Model               string          `json:"model"`
	Messages            []message       `json:"messages"`
	Stream              bool            `json:"stream,omitempty"`
	MaxTokens           int             `json:"max_tokens,omitempty"`
	Temperature         *float32        `json:"temperature,omitempty"`
	Tools               json.RawMessage `json:"tools,omitempty"`
	ToolChoice          json.RawMessage `json:"tool_choice,omitempty"`
	ReasoningEffort     string          `json:"reasoning_effort,omitempty"`
	ChatTemplateKwargs  json.RawMessage `json:"chat_template_kwargs,omitempty"`
	StreamOptions       json.RawMessage `json:"stream_options,omitempty"`
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		state, err := loadState(statePath, sessionKey)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth state unavailable"})
			return
		}
		proxyJSON(w, r, state, http.MethodGet, apiPrefix+"/api/v1/model-options?language=zh-CN", nil)
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		state, err := loadState(statePath, sessionKey)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth state unavailable"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil || req.Model == "" || len(req.Messages) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model and messages are required"})
			return
		}
		upstreamBody, err := buildUpstreamBody(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid messages"})
			return
		}
		proxyChat(w, r, state, upstreamBody, req.Stream || acceptsSSE(r))
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "teleagent2api listening on http://%s\n", addr)
	return server.ListenAndServe()
}

func loadState(path, sessionKey string) (authState, error) {
	if path != "" || sessionKey != "" || os.Getenv("TELEAGENT_AUTH_STATE_FILE") != "" || os.Getenv("TELEAGENT_SESSION_KEY") != "" {
		return loadEncryptedState(path, sessionKey)
	}
	return loadDesktopState()
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
	Scheme         string `json:"scheme"`
}

func loadDesktopState() (authState, error) {
	device, err := readDeviceMeta()
	if err != nil {
		return authState{}, err
	}
	matches, err := ownerTokenPaths()
	if err != nil {
		return authState{}, err
	}
	var last error
	for _, tokenPath := range matches {
		state, err := decryptOwnerToken(tokenPath, device)
		if err == nil {
			return state, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("owner token not found")
	}
	return authState{}, last
}

func teleAgentRoots() ([]string, error) {
	var homes []string
	if runtime.GOOS == "windows" {
		for _, key := range []string{"USERPROFILE", "HOME"} {
			if value := strings.TrimSpace(os.Getenv(key)); value != "" {
				homes = append(homes, value)
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	if len(homes) == 0 {
		return nil, errors.New("home directory not found")
	}
	seen := map[string]bool{}
	var roots []string
	for _, home := range homes {
		root := filepath.Clean(filepath.Join(home, ".local", "share", "TeleAgent"))
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func ownerTokenPaths() ([]string, error) {
	roots, err := teleAgentRoots()
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, root := range roots {
		found, _ := filepath.Glob(filepath.Join(root, "users", "*", "app-auth", "token.json"))
		matches = append(matches, found...)
	}
	return matches, nil
}

func readDeviceMeta() (authState, error) {
	roots, err := teleAgentRoots()
	if err != nil {
		return authState{}, err
	}
	var last error
	for _, root := range roots {
		raw, err := os.ReadFile(filepath.Join(root, "app-auth", "device-meta.json"))
		if err != nil {
			last = err
			continue
		}
		var state authState
		if err := json.Unmarshal(raw, &state); err != nil {
			return authState{}, err
		}
		if state.InstallID == "" {
			return authState{}, errors.New("install id missing")
		}
		return state, nil
	}
	if last == nil {
		last = errors.New("device metadata not found")
	}
	return authState{}, last
}

func decryptOwnerToken(tokenPath string, device authState) (authState, error) {
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return authState{}, err
	}
	var file ownerTokenFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return authState{}, err
	}
	if file.Version != 1 || file.EncryptedToken == "" {
		return authState{}, errors.New("unsupported owner token")
	}
	if file.Scheme == "safe_storage" {
		if runtime.GOOS != "windows" {
			return authState{}, errors.New("safe_storage token requires Windows DPAPI")
		}
		plain, err := decryptWindowsSafeStorage(file.EncryptedToken)
		if err != nil {
			return authState{}, err
		}
		device.Token = plain
		if device.Token == "" {
			return authState{}, errors.New("empty owner token")
		}
		return device, nil
	}
	if file.Scheme != "local" {
		return authState{}, errors.New("unsupported owner token")
	}
	key, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "local-key"))
	if err != nil {
		return authState{}, err
	}
	if len(key) != 32 {
		return authState{}, errors.New("invalid local key")
	}
	payload, err := base64.StdEncoding.DecodeString(file.EncryptedToken)
	if err != nil {
		return authState{}, err
	}
	if len(payload) <= 28 {
		return authState{}, errors.New("truncated owner token")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return authState{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return authState{}, err
	}
	plain, err := gcm.Open(nil, payload[:12], append(payload[28:], payload[12:28]...), nil)
	if err != nil {
		return authState{}, err
	}
	device.Token = string(plain)
	if device.Token == "" {
		return authState{}, errors.New("empty owner token")
	}
	return device, nil
}


func decryptWindowsSafeStorage(encoded string) (string, error) {
	script := `$ErrorActionPreference='Stop'; Add-Type -TypeDefinition @"
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
public static class TeleAgentDpapi {
  [StructLayout(LayoutKind.Sequential)] struct Blob { public int cb; public IntPtr pb; }
  [DllImport("crypt32.dll", SetLastError=true)] static extern bool CryptUnprotectData(ref Blob inb, IntPtr desc, IntPtr ent, IntPtr res, IntPtr prompt, int flags, out Blob outb);
  public static string Open(string b64) {
    byte[] data = Convert.FromBase64String(b64);
    if (data.Length > 5 && data[0]==118 && data[1]==49 && data[2]==48) data = data.Skip(5).ToArray();
    Blob input = new Blob { cb = data.Length, pb = Marshal.AllocHGlobal(data.Length) };
    Marshal.Copy(data, 0, input.pb, data.Length);
    Blob output;
    try {
      if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out output)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(input.pb); }
    try {
      byte[] plain = new byte[output.cb];
      Marshal.Copy(output.pb, plain, 0, output.cb);
      return Encoding.UTF8.GetString(plain);
    } finally { if (output.pb != IntPtr.Zero) Marshal.FreeHGlobal(output.pb); }
  }
}
"@; [TeleAgentDpapi]::Open([Console]::In.ReadToEnd().Trim())`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Stdin = strings.NewReader(encoded)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("Windows safe storage decryption failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
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

func proxyJSON(w http.ResponseWriter, r *http.Request, state authState, method, path string, body []byte) {
	resp, err := signedRequest(r, state, method, path, body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream unavailable"})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func proxyChat(w http.ResponseWriter, r *http.Request, state authState, body []byte, stream bool) {
	resp, err := signedRequest(r, state, http.MethodPost, chatPath, body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream unavailable"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !stream {
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
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
	req.Header.Set("X-OS-Type", "Linux")
	req.Header.Set("X-Device-Os", "linux")
	req.Header.Set("X-Teleai-Client-Type", "desktop")
	return http.DefaultClient.Do(req)
}

func sign(state authState, method, uri string, body []byte, timestamp, nonce, version string) map[string]string {
	bodyHash := hex.EncodeToString(sum256(body))
	payloadHash := hmacHex(jwtThirdSegment(state.Token), strings.Join([]string{authPrefix, state.Token, state.InstallID, timestamp, nonce}, "/"))
	signature := hmacHex(payloadHash, strings.Join([]string{
		authPrefix, strings.ToUpper(method), uri, timestamp, nonce, version, bodyHash,
	}, "\n"))
	headers := map[string]string{
		"X-Token":                    state.Token,
		"X-SuperAgent-Timestamp":     timestamp,
		"X-SuperAgent-Nonce":         nonce,
		"X-SuperAgent-Sign-Version":  "v1",
		"X-SuperAgent-Signature":     signature,
		"X-App-Version":              version,
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

type sseScanner struct {
	r   io.Reader
	buf []byte
	line string
	err error
}

func newSSEScanner(r io.Reader) *sseScanner { return &sseScanner{r: r, buf: make([]byte, 0, 4096)} }

func (s *sseScanner) Scan() bool {
	for {
		if i := bytes.IndexByte(s.buf, '\n'); i >= 0 {
			s.line = strings.TrimRight(string(s.buf[:i]), "\r")
			s.buf = s.buf[i+1:]
			return true
		}
		tmp := make([]byte, 4096)
		n, err := s.r.Read(tmp)
		s.buf = append(s.buf, tmp[:n]...)
		if err != nil {
			if len(s.buf) > 0 && errors.Is(err, io.EOF) {
				s.line = string(s.buf)
				s.buf = nil
				return true
			}
			s.err = err
			return false
		}
	}
}

func (s *sseScanner) Text() string { return s.line }
func (s *sseScanner) Err() error {
	if errors.Is(s.err, io.EOF) {
		return nil
	}
	return s.err
}
