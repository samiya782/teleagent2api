package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenV10RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	plain := []byte("header.payload.signature")
	sealed := gcm.Seal(nil, nonce, plain, nil)
	payload := append(append([]byte("v10"), nonce...), sealed...)
	got, err := openV10(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestNormalizeAndPickSessionToken(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	old := time.Now().Add(-time.Hour).Unix()
	fresh := testJWT(t, exp)
	stale := testJWT(t, old)
	if got := normalizeSessionToken("I7Kp2X:" + fresh); got != fresh {
		t.Fatalf("prefix was not removed")
	}
	if normalizeSessionToken("oper-token") != "" {
		t.Fatal("non jwt accepted")
	}
	got, err := pickSessionToken([]string{stale, "prefix:" + fresh})
	if err != nil || got != fresh {
		t.Fatalf("pick failed: %v", err)
	}
	if _, err := pickSessionToken([]string{stale}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestReadCookieTokens(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Cookies")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create table cookies (host_key text, name text, value text, encrypted_value blob)`); err != nil {
		t.Fatal(err)
	}
	token := testJWT(t, time.Now().Add(time.Hour).Unix())
	if _, err := db.Exec(`insert into cookies values (?, ?, ?, ?)`, "agent.teleai.com.cn", "operationToken", "ab:"+token, []byte{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into cookies values (?, ?, ?, ?)`, ".agent.teleai.com.cn", "x-token", "", []byte("v20fixture")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into cookies values (?, ?, ?, ?)`, "unrelatedteleai.com.cn", "x-token", token, []byte{}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	got, err := readCookieTokens(cookieDB{path: dbPath})
	if !errors.Is(err, errAppBoundCookie) {
		t.Fatalf("missing App-Bound Encryption diagnosis: %v", err)
	}
	if len(got) != 1 || got[0] != token {
		t.Fatalf("cookie token mismatch")
	}
}

func TestLoadExplicitWebToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	t.Setenv(webTokenFileEnv, path)
	t.Setenv("TELEAGENT_AUTH_STATE_FILE", "")
	t.Setenv("TELEAGENT_SESSION_KEY", "")
	token := testJWT(t, time.Now().Add(time.Hour).Unix())
	if err := os.WriteFile(path, []byte("\ufeff"+token+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := loadState("", "")
	if err != nil || state.Token != token || state.OSType != "Web" || state.ClientType != "web" {
		t.Fatalf("web token state was not loaded: %v", err)
	}
	for _, raw := range []string{"malformed", testJWT(t, time.Now().Add(-time.Hour).Unix()), strings.Repeat("x", (16<<10)+1)} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadState("", ""); err == nil || strings.Contains(err.Error(), raw) {
			t.Fatal("invalid file accepted or its contents exposed")
		}
	}
}

func TestSafeStorageTokenWhenPresent(t *testing.T) {
	roots, err := teleAgentRoots()
	if err != nil {
		t.Fatal(err)
	}
	if extra := wslWindowsDataRoot(); extra != "" {
		roots = append(roots, extra)
	}
	found := false
	for _, root := range roots {
		device, err := readDeviceMetaFile(filepath.Join(root, "app-auth", "device-meta.json"))
		if err != nil {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(root, "users", "*", "app-auth", "token.json"))
		for _, tokenPath := range matches {
			raw, err := os.ReadFile(tokenPath)
			if err != nil {
				t.Fatal(err)
			}
			var file ownerTokenFile
			if err := json.Unmarshal(raw, &file); err != nil {
				t.Fatal(err)
			}
			if file.Scheme != "safe_storage" {
				continue
			}
			found = true
			state, err := decryptOwnerToken(tokenPath, device)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(state.Token, ".") != 2 || len(state.Token) < 100 || jwtExpired(state.Token) {
				t.Fatal("unexpected safe storage token")
			}
			if state.InstallID == "" {
				t.Fatal("install id missing")
			}
		}
	}
	if !found {
		t.Skip("no safe_storage token on this machine")
	}
}

func testJWT(t *testing.T, exp int64) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"exp": exp})
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}
