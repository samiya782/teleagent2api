package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const refreshPath = apiPrefix + "/cowork/auth/token-refresh"

func startRenewal() {
	if refreshDisabled() {
		fmt.Fprintln(os.Stderr, "token refresh disabled")
		return
	}
	go func() {
		runRenewal()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			runRenewal()
		}
	}()
}

func refreshDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TELEAGENT_REFRESH"))) {
	case "0", "false", "off":
		return true
	default:
		return false
	}
}

func runRenewal() {
	src, err := loadDesktopSource()
	if err != nil {
		fmt.Fprintf(os.Stderr, "token refresh skipped: %s\n", redactSecrets(err.Error()))
		return
	}
	status, err := renewDesktop(context.Background(), src, nil, time.Now(), upstreamHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token refresh failed: %s\n", redactSecrets(err.Error()))
		return
	}
	if status != "" {
		fmt.Fprintf(os.Stderr, "token refresh %s\n", status)
	}
}

func renewDesktop(ctx context.Context, src desktopSource, client *http.Client, now time.Time, base string) (string, error) {
	if src.TokenPath == "" || src.State.Token == "" {
		return "skipped: no desktop token", nil
	}
	unlock, err := acquireRenewLock(src.TokenPath)
	if err != nil {
		if err == errRenewBusy {
			return "skipped: refresh already running", nil
		}
		return "", err
	}
	defer unlock()
	day := now.Format("2006-01-02")
	if readRenewalDay(src.TokenPath) == day {
		return "skipped: already attempted today", nil
	}
	record, err := decryptOwnerToken(src.TokenPath, src.State)
	if err != nil {
		return "", err
	}
	if jwtExpired(record.Token) {
		return "skipped: owner token expired", nil
	}
	if err := writeRenewalDay(src.TokenPath, day); err != nil {
		return "", err
	}
	record.OSType = src.State.OSType
	record.DeviceOS = src.State.DeviceOS
	record.ClientType = src.State.ClientType
	next, expiresAt, absolute, err := requestRefresh(ctx, client, base, record, now)
	if err != nil {
		return "", err
	}
	if err := persistRenewedToken(src.TokenPath, record.Token, next, now, expiresAt, absolute); err != nil {
		return "", err
	}
	ttl := expiresAt.Sub(now).Round(time.Second)
	return fmt.Sprintf("succeeded ttl=%s", ttl), nil
}

func requestRefresh(ctx context.Context, client *http.Client, base string, state authState, now time.Time) (string, time.Time, *time.Time, error) {
	status, body, err := postRefresh(ctx, client, base, state, false)
	if err != nil {
		status, body, err = postRefresh(ctx, client, base, state, false)
	}
	if err != nil {
		return "", time.Time{}, nil, err
	}
	if status == http.StatusUnauthorized {
		status, body, err = postRefresh(ctx, client, base, state, true)
		if err != nil {
			return "", time.Time{}, nil, err
		}
	}
	if status < 200 || status >= 300 {
		_, _, _, biz, perr := parseRefresh(body, now)
		if perr != nil && biz != 0 {
			return "", time.Time{}, nil, fmt.Errorf("token refresh http %d code %d", status, biz)
		}
		return "", time.Time{}, nil, fmt.Errorf("token refresh http %d", status)
	}
	token, expiresAt, absolute, biz, err := parseRefresh(body, now)
	if err != nil {
		if biz != 0 {
			return "", time.Time{}, nil, fmt.Errorf("token refresh http %d code %d", status, biz)
		}
		return "", time.Time{}, nil, err
	}
	return token, expiresAt, absolute, nil
}

func postRefresh(ctx context.Context, client *http.Client, base string, state authState, signed bool) (int, []byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	callCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(base, "/") + refreshPath
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, strings.NewReader(""))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if signed {
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		nonce := newNonce()
		for key, value := range sign(state, http.MethodPost, refreshPath, []byte{}, timestamp, nonce, appVersion) {
			req.Header.Set(key, value)
		}
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Nonce", nonce)
		osType, deviceOS, clientType := state.OSType, state.DeviceOS, state.ClientType
		if osType == "" {
			osType, deviceOS, clientType = "Linux", "linux", "desktop"
			if strings.EqualFold(state.DeviceOS, "windows") {
				osType, deviceOS, clientType = "Windows", "windows", "desktop"
			}
		}
		req.Header.Set("X-OS-Type", osType)
		req.Header.Set("X-Device-Os", deviceOS)
		req.Header.Set("X-Teleai-Client-Type", clientType)
	} else {
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		req.Header.Set("X-Token", state.Token)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Nonce", newUUID())
		req.Header.Set("X-App-Version", appVersion)
		if state.OSType != "" {
			req.Header.Set("X-OS-Type", state.OSType)
		}
		if state.DeviceID != "" {
			req.Header.Set("X-SuperAgent-Device-Id", state.DeviceID)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func parseRefresh(body []byte, now time.Time) (string, time.Time, *time.Time, int, error) {
	var root map[string]any
	if err := jsonUnmarshal(body, &root); err != nil {
		return "", time.Time{}, nil, 0, err
	}
	biz := firstBiz(root)
	token, expiresIn, absoluteRaw := tokenFields(root)
	if data, ok := root["data"].(map[string]any); ok {
		if nestedBiz := firstBiz(data); nestedBiz != 0 {
			biz = nestedBiz
		}
		if t, e, a := tokenFields(data); t != "" {
			token, expiresIn, absoluteRaw = t, e, a
		}
		if nested, ok := data["token"].(map[string]any); ok {
			if t, e, a := tokenFields(nested); t != "" {
				token, expiresIn, absoluteRaw = t, e, a
			}
		}
	}
	if terminalRefreshCode(biz) {
		return "", time.Time{}, nil, biz, fmt.Errorf("token refresh rejected code %d", biz)
	}
	if token == "" || expiresIn <= 0 {
		if biz != 0 {
			return "", time.Time{}, nil, biz, fmt.Errorf("token refresh rejected code %d", biz)
		}
		return "", time.Time{}, nil, biz, fmt.Errorf("token refresh response missing accessToken")
	}
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)
	var absolute *time.Time
	if absoluteRaw > 0 {
		ms := absoluteRaw
		if ms < 1e11 {
			ms *= 1000
		}
		stamp := time.UnixMilli(int64(ms))
		if stamp.After(now) {
			absolute = &stamp
		}
	}
	return strings.TrimSpace(token), expiresAt, absolute, biz, nil
}

func tokenFields(obj map[string]any) (string, int64, float64) {
	token, _ := obj["accessToken"].(string)
	return strings.TrimSpace(token), asInt64(obj["expiresIn"]), asFloat(obj["absoluteExpiresAt"])
}

func firstBiz(obj map[string]any) int {
	for _, key := range []string{"responseCode", "code"} {
		if n, ok := asNumber(obj[key]); ok {
			return int(n)
		}
	}
	return 0
}

func asInt64(v any) int64 {
	n, ok := asNumber(v)
	if !ok {
		return 0
	}
	return int64(n)
}

func asFloat(v any) float64 {
	n, ok := asNumber(v)
	if !ok {
		return 0
	}
	return n
}

func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		var f float64
		if _, err := fmt.Sscan(n, &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

func jsonUnmarshal(body []byte, dest any) error {
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("invalid refresh response")
	}
	return nil
}

func terminalRefreshCode(code int) bool {
	switch code {
	case 40112, 40113, 40114, 40115, 40116:
		return true
	default:
		return false
	}
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*)*`)

func redactSecrets(text string) string {
	return jwtPattern.ReplaceAllString(text, "[redacted]")
}
