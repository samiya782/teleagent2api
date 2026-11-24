package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type desktopSource struct {
	State     authState
	TokenPath string
}

func loadDesktopState() (authState, error) {
	src, err := loadDesktopSource()
	if err != nil {
		return authState{}, err
	}
	return src.State, nil
}

func loadDesktopSource() (desktopSource, error) {
	roots, err := teleAgentRoots()
	if err != nil {
		return desktopSource{}, err
	}
	src, last := loadDesktopFrom(roots)
	if last == nil {
		return src, nil
	}
	if extra := wslWindowsDataRoot(); extra != "" && !containsPath(roots, extra) {
		src, extraErr := loadDesktopFrom([]string{extra})
		if extraErr == nil {
			return src, nil
		}
		last = errors.Join(last, extraErr)
	}
	return desktopSource{}, last
}

func loadDesktopFrom(roots []string) (desktopSource, error) {
	var last error
	for _, root := range roots {
		device, err := readDeviceMetaFile(filepath.Join(root, "app-auth", "device-meta.json"))
		if err != nil {
			last = err
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(root, "users", "*", "app-auth", "token.json"))
		if len(matches) == 0 {
			last = errors.New("owner token not found")
			continue
		}
		for _, tokenPath := range matches {
			state, err := decryptOwnerToken(tokenPath, device)
			if err != nil {
				last = err
				continue
			}
			if jwtExpired(state.Token) {
				last = errors.New("owner token expired")
				continue
			}
			applyDesktopProfile(&state, root)
			return desktopSource{State: state, TokenPath: tokenPath}, nil
		}
	}
	if last == nil {
		last = errors.New("owner token not found")
	}
	return desktopSource{}, last
}

func wslWindowsDataRoot() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	home := windowsUserHome()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "share", "TeleAgent")
}

func containsPath(paths []string, want string) bool {
	want = filepath.Clean(want)
	for _, path := range paths {
		if filepath.Clean(path) == want {
			return true
		}
	}
	return false
}

const webTokenFileEnv = "TELEAGENT_WEB_TOKEN_FILE"

var errAppBoundCookie = errors.New("browser cookie uses App-Bound Encryption (v20); use a signed-in TeleAgent desktop app or set TELEAGENT_WEB_TOKEN_FILE")

func loadWebState() (authState, error) {
	tokens, cookieErr := webSessionTokens()
	token, err := pickSessionToken(tokens)
	if err != nil {
		return authState{}, errors.Join(err, cookieErr)
	}
	return webState(token), nil
}

func loadWebTokenFile(path string) (authState, error) {
	file, err := os.Open(path)
	if err != nil {
		return authState{}, fmt.Errorf("open web token file: %w", err)
	}
	defer file.Close()
	const maxTokenSize = 16 << 10
	raw, err := io.ReadAll(io.LimitReader(file, maxTokenSize+1))
	if err != nil {
		return authState{}, fmt.Errorf("read web token file: %w", err)
	}
	if len(raw) > maxTokenSize {
		return authState{}, errors.New("web token file exceeds 16 KiB")
	}
	token := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
	if _, ok := jwtExpiry(token); !ok || normalizeSessionToken(token) != token {
		return authState{}, errors.New("web token file must contain one TeleAgent JWT with an expiration")
	}
	if jwtExpired(token) {
		return authState{}, errors.New("web token file has expired")
	}
	return webState(token), nil
}

func webState(token string) authState {
	device, _ := readDeviceMeta()
	device.Token = token
	device.OSType = "Web"
	device.DeviceOS = "web"
	device.ClientType = "web"
	return device
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
	seen := map[string]bool{}
	var roots []string
	add := func(root string) {
		root = filepath.Clean(root)
		if root == "" || seen[root] {
			return
		}
		seen[root] = true
		roots = append(roots, root)
	}
	for _, home := range homes {
		add(filepath.Join(home, ".local", "share", "TeleAgent"))
		if runtime.GOOS == "windows" {
			if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
				add(filepath.Join(appData, "TeleAgent"))
				add(filepath.Join(appData, "teleagent"))
			}
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("home directory not found")
	}
	return roots, nil
}

var (
	windowsHomeOnce sync.Once
	windowsHome     string
)

func windowsUserHome() string {
	windowsHomeOnce.Do(func() {
		if runtime.GOOS == "windows" {
			windowsHome, _ = os.UserHomeDir()
			return
		}
		ps := powershellExecutable()
		if ps == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := execOutput(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", "[Environment]::GetFolderPath('UserProfile')")
		if err != nil {
			return
		}
		windowsHome = windowsPathToLocal(strings.TrimSpace(out))
	})
	return windowsHome
}

func windowsPathToLocal(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || runtime.GOOS == "windows" {
		return path
	}
	if len(path) >= 3 && path[1] == ':' {
		drive := strings.ToLower(path[:1])
		rest := strings.ReplaceAll(path[2:], `\`, `/`)
		return filepath.Clean("/mnt/" + drive + rest)
	}
	return path
}

func readDeviceMeta() (authState, error) {
	roots, err := teleAgentRoots()
	if err != nil {
		return authState{}, err
	}
	var last error
	for _, root := range roots {
		state, err := readDeviceMetaFile(filepath.Join(root, "app-auth", "device-meta.json"))
		if err != nil {
			last = err
			continue
		}
		return state, nil
	}
	if last == nil {
		last = errors.New("device metadata not found")
	}
	return authState{}, last
}

func readDeviceMetaFile(path string) (authState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return authState{}, err
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
	plain, err := decryptOwnerValue(tokenPath, file.Scheme, file.EncryptedToken)
	if err != nil {
		return authState{}, err
	}
	device.Token = plain
	if device.Token == "" {
		return authState{}, errors.New("empty owner token")
	}
	return device, nil
}

func decryptOwnerValue(tokenPath, scheme, encoded string) (string, error) {
	if scheme == "local" {
		key, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "local-key"))
		if err != nil {
			return "", err
		}
		if len(key) != 32 {
			return "", errors.New("invalid local key")
		}
		payload, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", err
		}
		plain, err := openLocal(key, payload)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	if scheme != "safe_storage" && scheme != "" {
		return "", errors.New("unsupported owner token")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(tokenPath), "..", "..", ".."))
	return decryptSafeStorage(encoded, filepath.Join(root, "Local State"))
}

func encryptOwnerValue(tokenPath, scheme, plain string) (string, error) {
	if scheme == "local" {
		key, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "local-key"))
		if err != nil {
			return "", err
		}
		if len(key) != 32 {
			return "", errors.New("invalid local key")
		}
		payload, err := sealLocal(key, []byte(plain))
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(payload), nil
	}
	if scheme != "safe_storage" && scheme != "" {
		return "", errors.New("unsupported owner token")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(tokenPath), "..", "..", ".."))
	key, err := osCryptKey(filepath.Join(root, "Local State"))
	if err != nil {
		return "", err
	}
	payload, err := sealV10(key, []byte(plain))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}

func openLocal(key, payload []byte) ([]byte, error) {
	if len(payload) <= 28 {
		return nil, errors.New("truncated owner token")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, payload[:12], append(payload[28:], payload[12:28]...), nil)
}

func sealLocal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)
	tagAt := len(sealed) - gcm.Overhead()
	payload := make([]byte, 0, len(nonce)+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed[tagAt:]...)
	payload = append(payload, sealed[:tagAt]...)
	return payload, nil
}

func sealV10(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)
	payload := make([]byte, 0, 3+len(nonce)+len(sealed))
	payload = append(payload, []byte("v10")...)
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)
	return payload, nil
}

type storedMeta struct {
	Token             string `json:"token"`
	TokenIssuedAt     int64  `json:"tokenIssuedAt"`
	TokenExpiresAt    int64  `json:"tokenExpiresAt"`
	AbsoluteExpiresAt *int64 `json:"absoluteExpiresAt"`
	Generation        int64  `json:"generation"`
}

func persistRenewedToken(tokenPath, previous, next string, issuedAt, expiresAt time.Time, absolute *time.Time) error {
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	var file ownerTokenFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	if file.Version != 1 || file.EncryptedToken == "" {
		return errors.New("unsupported owner token")
	}
	current, err := decryptOwnerValue(tokenPath, file.Scheme, file.EncryptedToken)
	if err != nil {
		return err
	}
	if current != previous {
		return errors.New("owner token changed")
	}
	var meta storedMeta
	if file.EncryptedMeta != "" {
		if plain, err := decryptOwnerValue(tokenPath, file.Scheme, file.EncryptedMeta); err == nil {
			_ = json.Unmarshal([]byte(plain), &meta)
		}
	}
	generation := int64(1)
	if meta.Token != "" {
		generation = meta.Generation + 1
	}
	var absoluteMs *int64
	if absolute != nil {
		ms := absolute.UnixMilli()
		absoluteMs = &ms
	}
	meta = storedMeta{
		Token:             next,
		TokenIssuedAt:     issuedAt.UnixMilli(),
		TokenExpiresAt:    expiresAt.UnixMilli(),
		AbsoluteExpiresAt: absoluteMs,
		Generation:        generation,
	}
	metaPlain, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	encToken, err := encryptOwnerValue(tokenPath, file.Scheme, next)
	if err != nil {
		return err
	}
	encMeta, err := encryptOwnerValue(tokenPath, file.Scheme, string(metaPlain))
	if err != nil {
		return err
	}
	file.Version = 1
	file.EncryptedToken = encToken
	file.EncryptedMeta = encMeta
	return writeOwnerTokenFile(tokenPath, file)
}

func writeOwnerTokenFile(path string, file ownerTokenFile) error {
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return replaceAuthFile(path, append(raw, '\n'))
}

func replaceAuthFile(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return err
	}
	// Rename replaces the destination in one operation. If it fails, leave the existing file in place.
	return os.Rename(f.Name(), path)
}

func renewalSchedulePath(tokenPath string) string {
	return filepath.Join(filepath.Dir(tokenPath), "renewal-schedule.json")
}

func readRenewalDay(tokenPath string) string {
	raw, err := os.ReadFile(renewalSchedulePath(tokenPath))
	if err != nil {
		return ""
	}
	var schedule struct {
		LastAttemptDay string `json:"lastAttemptDay"`
	}
	if json.Unmarshal(raw, &schedule) != nil {
		return ""
	}
	return schedule.LastAttemptDay
}

func writeRenewalDay(tokenPath, day string) error {
	raw, err := json.MarshalIndent(struct {
		LastAttemptDay string `json:"lastAttemptDay"`
	}{LastAttemptDay: day}, "", "  ")
	if err != nil {
		return err
	}
	return replaceAuthFile(renewalSchedulePath(tokenPath), append(raw, '\n'))
}

func acquireRenewLock(tokenPath string) (func(), error) {
	path := filepath.Join(filepath.Dir(tokenPath), ".renewal.lock")
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		info, statErr := os.Stat(path)
		if statErr == nil && time.Since(info.ModTime()) > 2*time.Minute {
			os.Remove(path)
			continue
		}
		return nil, errRenewBusy
	}
	return nil, errRenewBusy
}

var errRenewBusy = errors.New("token refresh already running")

func decryptSafeStorage(encoded, localStatePath string) (string, error) {
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if bytes.HasPrefix(payload, []byte("v10")) {
		key, err := osCryptKey(localStatePath)
		if err != nil {
			return "", err
		}
		plain, err := openV10(key, payload)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	plain, err := dpapiUnprotect(payload)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func osCryptKey(localStatePath string) ([]byte, error) {
	raw, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("TeleAgent Local State: %w", err)
	}
	var state struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("os_crypt key not found")
	}
	keyBlob, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(keyBlob, []byte("DPAPI")) {
		keyBlob = keyBlob[len("DPAPI"):]
	}
	key, err := dpapiUnprotect(keyBlob)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("unexpected os_crypt key length")
	}
	return key, nil
}

func openV10(key, payload []byte) ([]byte, error) {
	if !bytes.HasPrefix(payload, []byte("v10")) || len(payload) < 3+12+16 {
		return nil, errors.New("truncated v10 payload")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, payload[3:15], payload[15:], nil)
}

func applyDesktopProfile(state *authState, root string) {
	if isWindowsRoot(root) {
		state.OSType = "Windows"
		state.DeviceOS = "windows"
	} else {
		state.OSType = "Linux"
		state.DeviceOS = "linux"
	}
	state.ClientType = "desktop"
}

func isWindowsRoot(root string) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	clean := strings.ToLower(filepath.ToSlash(root))
	return strings.Contains(clean, "/mnt/c/users/") || strings.Contains(clean, "/appdata/")
}

type cookieDB struct {
	path    string
	keyPath string
}

func webSessionTokens() ([]string, error) {
	var tokens []string
	var last error
	for _, db := range cookieDatabases() {
		found, err := readCookieTokens(db)
		tokens = append(tokens, found...)
		// Keep an App-Bound error visible even when other profiles are absent.
		if err != nil && !os.IsNotExist(err) && !errors.Is(last, errAppBoundCookie) {
			last = err
		}
	}
	return tokens, last
}

func cookieDatabases() []cookieDB {
	var out []cookieDB
	roots, _ := teleAgentRoots()
	if extra := wslWindowsDataRoot(); extra != "" {
		roots = append(roots, extra)
	}
	for _, root := range roots {
		key := filepath.Join(root, "Local State")
		for _, rel := range []string{"Cookies", filepath.Join("Network", "Cookies")} {
			out = append(out, cookieDB{path: filepath.Join(root, rel), keyPath: key})
		}
		matches, _ := filepath.Glob(filepath.Join(root, "Partitions", "*"))
		for _, partition := range matches {
			for _, rel := range []string{"Cookies", filepath.Join("Network", "Cookies")} {
				out = append(out, cookieDB{path: filepath.Join(partition, rel), keyPath: key})
			}
		}
	}
	out = append(out, browserCookieDatabases()...)
	return out
}

func browserCookieDatabases() []cookieDB {
	var homes []string
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	if runtime.GOOS != "windows" {
		if home := windowsUserHome(); home != "" {
			homes = append(homes, home)
		}
	}
	var out []cookieDB
	for _, home := range homes {
		roots := []string{
			filepath.Join(home, ".config", "google-chrome"),
			filepath.Join(home, ".config", "chromium"),
			filepath.Join(home, ".config", "microsoft-edge"),
			filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data"),
		}
		if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" && runtime.GOOS == "windows" {
			roots = append(roots,
				filepath.Join(local, "Google", "Chrome", "User Data"),
				filepath.Join(local, "Microsoft", "Edge", "User Data"),
			)
		}
		for _, root := range roots {
			key := filepath.Join(root, "Local State")
			profiles, _ := filepath.Glob(filepath.Join(root, "Profile *"))
			profiles = append([]string{filepath.Join(root, "Default")}, profiles...)
			for _, profile := range profiles {
				for _, rel := range []string{filepath.Join("Network", "Cookies"), "Cookies"} {
					out = append(out, cookieDB{path: filepath.Join(profile, rel), keyPath: key})
				}
			}
		}
	}
	return out
}

func readCookieTokens(db cookieDB) ([]string, error) {
	info, err := os.Stat(db.path)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "teleagent-cookies-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	copied := filepath.Join(dir, "Cookies")
	if err := copyFile(db.path, copied); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		src := db.path + suffix
		if _, err := os.Stat(src); err == nil {
			_ = copyFile(src, copied+suffix)
		}
	}
	conn, err := sql.Open("sqlite", "file:"+filepath.ToSlash(copied)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.Query(`select value, encrypted_value from cookies where name in ('operationToken', 'x-token') and host_key in ('agent.teleai.com.cn', '.agent.teleai.com.cn', 'teleai.com.cn', '.teleai.com.cn')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var key []byte
	var tokens []string
	appBound := false
	for rows.Next() {
		var value string
		var encrypted []byte
		if err := rows.Scan(&value, &encrypted); err != nil {
			return nil, err
		}
		if token := normalizeSessionToken(value); token != "" {
			tokens = append(tokens, token)
			continue
		}
		if bytes.HasPrefix(encrypted, []byte("v20")) {
			appBound = true
			continue
		}
		if !bytes.HasPrefix(encrypted, []byte("v10")) {
			continue
		}
		if key == nil {
			key, err = osCryptKey(db.keyPath)
			if err != nil {
				continue
			}
		}
		plain, err := openV10(key, encrypted)
		if err != nil {
			continue
		}
		if token := normalizeSessionToken(string(plain)); token != "" {
			tokens = append(tokens, token)
		}
	}
	err = rows.Err()
	if appBound {
		err = errors.Join(err, errAppBoundCookie)
	}
	return tokens, err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func normalizeSessionToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if i := strings.Index(value, "eyJ"); i > 0 && i <= 16 {
		value = value[i:]
	}
	if strings.Count(value, ".") != 2 || !strings.HasPrefix(value, "eyJ") {
		return ""
	}
	return value
}

func pickSessionToken(tokens []string) (string, error) {
	now := time.Now().Unix()
	var best string
	var bestExp int64
	expired := false
	for _, token := range tokens {
		token = normalizeSessionToken(token)
		if token == "" {
			continue
		}
		exp, ok := jwtExpiry(token)
		if ok && exp <= now {
			expired = true
			continue
		}
		if !ok {
			exp = 0
		}
		if best == "" || exp >= bestExp {
			best = token
			bestExp = exp
		}
	}
	if best != "" {
		return best, nil
	}
	if expired {
		return "", errors.New("web session expired")
	}
	return "", errors.New("web session cookie not found")
}

func jwtExpired(token string) bool {
	exp, ok := jwtExpiry(token)
	return ok && exp <= time.Now().Unix()
}

func jwtExpiry(token string) (int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Exp == 0 {
		return 0, false
	}
	return claims.Exp, true
}

func execOutput(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
