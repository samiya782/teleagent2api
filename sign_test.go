package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignMatchesKnownVector(t *testing.T) {
	state := authState{Token: "header.payload.signature-material", DeviceID: "device", InstallID: "install"}
	body := []byte(`{"model":"chat-pro"}`)
	got := sign(state, "POST", "/superCowork/sapi/api/v1/chat/completions", body, "1710000000", "nonce-1", "3.0.0-rc.1")
	if got["X-Token"] != state.Token || got["X-SuperAgent-Timestamp"] != "1710000000" || got["X-SuperAgent-Nonce"] != "nonce-1" {
		t.Fatalf("header mapping mismatch")
	}
	if got["X-SuperAgent-Sign-Version"] != "v1" || len(got["X-SuperAgent-Signature"]) != 64 {
		t.Fatalf("signature format mismatch")
	}
	payload := strings.Join([]string{authPrefix, state.Token, state.InstallID, "1710000000", "nonce-1"}, "/")
	hash := hmacHex(jwtThirdSegment(state.Token), payload)
	bodyHash := hex.EncodeToString(sum256(body))
	want := hmacHex(hash, strings.Join([]string{authPrefix, "POST", "/superCowork/sapi/api/v1/chat/completions", "1710000000", "nonce-1", "3.0.0-rc.1", bodyHash}, "\n"))
	if got["X-SuperAgent-Signature"] != want {
		t.Fatalf("signature mismatch")
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	keyText := "local-session-key"
	plain := []byte(`{"token":"a.b.c","deviceId":"d","installId":"i"}`)
	sum := sha256.Sum256([]byte(keyText))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, iv, plain, nil)
	tag := sealed[len(sealed)-gcm.Overhead():]
	enc := encryptedAuth{
		Version: "v1",
		IV: base64.RawURLEncoding.EncodeToString(iv),
		Tag: base64.RawURLEncoding.EncodeToString(tag),
		Ciphertext: base64.RawURLEncoding.EncodeToString(sealed[:len(sealed)-len(tag)]),
	}
	got, err := decrypt(enc, keyText)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("plaintext mismatch")
	}
	var state authState
	if err := json.Unmarshal(got, &state); err != nil || state.InstallID != "i" {
		t.Fatal(err)
	}
}
