package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSealLocalAndV10RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plain := []byte("desktop-token")
	local, err := sealLocal(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openLocal(key, local)
	if err != nil || string(opened) != string(plain) {
		t.Fatalf("local round trip: %v", err)
	}
	v10, err := sealV10(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = openV10(key, v10)
	if err != nil || string(opened) != string(plain) {
		t.Fatalf("v10 round trip: %v", err)
	}
}

func TestParseRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	token, expiresAt, absolute, biz, err := parseRefresh([]byte(`{"code":0,"data":{"accessToken":"abc.def.ghi","expiresIn":3600,"absoluteExpiresAt":4102444800}}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if token != "abc.def.ghi" || biz != 0 || !expiresAt.Equal(now.Add(time.Hour)) || absolute == nil {
		t.Fatalf("parsed token=%t exp=%s abs=%v biz=%d", token != "", expiresAt.Sub(now), absolute, biz)
	}
	if _, _, _, _, err := parseRefresh([]byte(`{"code":40114}`), now); err == nil || !strings.Contains(err.Error(), "40114") {
		t.Fatalf("expected terminal code, got %v", err)
	}
}

func TestRenewSkipsAfterAttemptToday(t *testing.T) {
	token := testJWT(t, time.Now().Add(48*time.Hour).Unix())
	path := writeLocalOwner(t, t.TempDir(), token, 2)
	now := time.Now()
	if err := writeRenewalDay(path, now.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer server.Close()
	status, err := renewDesktop(context.Background(), desktopSource{State: authState{Token: token, OSType: "Linux"}, TokenPath: path}, server.Client(), now, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if hit || !strings.Contains(status, "already attempted") {
		t.Fatalf("status=%s hit=%v", status, hit)
	}
}

func TestRenewPersistsNewToken(t *testing.T) {
	oldToken := testJWT(t, time.Now().Add(48*time.Hour).Unix())
	newToken := testJWT(t, time.Now().Add(72*time.Hour).Unix())
	path := writeLocalOwner(t, t.TempDir(), oldToken, 4)
	var sawPlain, sawSigned bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != refreshPath || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := readBody(r)
		if body != "" {
			t.Errorf("expected empty body, len=%d", len(body))
		}
		if r.Header.Get("X-SuperAgent-Signature") != "" {
			sawSigned = true
		} else {
			sawPlain = true
			if r.Header.Get("X-Token") == "" || r.Header.Get("X-Timestamp") == "" || r.Header.Get("X-Nonce") == "" || r.Header.Get("X-App-Version") != appVersion {
				t.Errorf("plain refresh headers incomplete")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"data": map[string]any{"accessToken": newToken, "expiresIn": 3600, "absoluteExpiresAt": 4102444800},
		})
	}))
	defer server.Close()
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.Local)
	status, err := renewDesktop(context.Background(), desktopSource{
		State:     authState{Token: oldToken, DeviceID: "device", InstallID: "install", OSType: "Linux", DeviceOS: "linux", ClientType: "desktop"},
		TokenPath: path,
	}, server.Client(), now, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !sawPlain || !sawSigned || !strings.Contains(status, "succeeded") {
		t.Fatalf("status=%s plain=%v signed=%v", status, sawPlain, sawSigned)
	}
	got, err := decryptOwnerToken(path, authState{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != newToken {
		t.Fatal("persisted token was not replaced")
	}
	meta := readStoredMeta(t, path)
	if meta.Token != newToken || meta.Generation != 5 || meta.TokenExpiresAt != now.Add(time.Hour).UnixMilli() || meta.AbsoluteExpiresAt == nil {
		t.Fatalf("meta generation=%d exp=%d abs=%v token_match=%v", meta.Generation, meta.TokenExpiresAt, meta.AbsoluteExpiresAt != nil, meta.Token == newToken)
	}
	if readRenewalDay(path) != "2026-11-16" {
		t.Fatalf("schedule day %s", readRenewalDay(path))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), ".renewal.lock")); !os.IsNotExist(err) {
		t.Fatal("renewal lock left behind")
	}
}

func writeLocalOwner(t *testing.T, dir, token string, generation int64) string {
	t.Helper()
	auth := filepath.Join(dir, "users", "owner", "app-auth")
	if err := os.MkdirAll(auth, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(auth, "token.json")
	if err := os.WriteFile(filepath.Join(auth, "local-key"), bytes.Repeat([]byte("k"), 32), 0o600); err != nil {
		t.Fatal(err)
	}
	enc, err := encryptOwnerValue(path, "local", token)
	if err != nil {
		t.Fatal(err)
	}
	metaRaw, err := json.Marshal(storedMeta{Token: token, TokenIssuedAt: 1, TokenExpiresAt: 2, Generation: generation})
	if err != nil {
		t.Fatal(err)
	}
	encMeta, err := encryptOwnerValue(path, "local", string(metaRaw))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerTokenFile(path, ownerTokenFile{
		Version: 1, EncryptedToken: enc, Encrypted: false, Scheme: "local", EncryptedMeta: encMeta,
	}); err != nil {
		t.Fatal(err)
	}
	return path
}

func readStoredMeta(t *testing.T, path string) storedMeta {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file ownerTokenFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	plain, err := decryptOwnerValue(path, file.Scheme, file.EncryptedMeta)
	if err != nil {
		t.Fatal(err)
	}
	var meta storedMeta
	if err := json.Unmarshal([]byte(plain), &meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func readBody(r *http.Request) (string, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r.Body)
	return buf.String(), err
}

func TestAuthFileReplacementPreservesDestinationOnFailure(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "token.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerTokenFile(path, ownerTokenFile{Version: 1}); err == nil {
		t.Fatal("expected replacement to fail when destination is a directory")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("existing destination was changed: %v", err)
	}
	children, err := os.ReadDir(parent)
	if err != nil || len(children) != 1 {
		t.Fatalf("temporary file left after failed replacement: %v (%v)", children, err)
	}
}
