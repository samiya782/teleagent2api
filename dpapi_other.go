//go:build !windows

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func dpapiUnprotect(data []byte) ([]byte, error) {
	ps := powershellExecutable()
	if ps == "" {
		return nil, errors.New("Windows DPAPI is unavailable from this process")
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", dpapiScript)
	cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(data))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Windows DPAPI decryption failed: %w", err)
	}
	plain, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, errors.New("Windows DPAPI returned an unreadable result")
	}
	return plain, nil
}

func powershellExecutable() string {
	for _, candidate := range []string{
		"powershell.exe",
		`/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`,
	} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

const dpapiScript = `$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class TeleAgentDpapi {
  [StructLayout(LayoutKind.Sequential)] struct Blob { public int cb; public IntPtr pb; }
  [DllImport("crypt32.dll", SetLastError=true)] static extern bool CryptUnprotectData(ref Blob inb, IntPtr desc, IntPtr ent, IntPtr res, IntPtr prompt, int flags, out Blob outb);
  public static string Open(string b64) {
    byte[] data = Convert.FromBase64String(b64);
    Blob input = new Blob { cb = data.Length, pb = Marshal.AllocHGlobal(data.Length) };
    Marshal.Copy(data, 0, input.pb, data.Length);
    Blob output;
    try {
      if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out output)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(input.pb); }
    try {
      byte[] plain = new byte[output.cb];
      Marshal.Copy(output.pb, plain, 0, output.cb);
      return Convert.ToBase64String(plain);
    } finally { if (output.pb != IntPtr.Zero) Marshal.FreeHGlobal(output.pb); }
  }
}
"@
[TeleAgentDpapi]::Open([Console]::In.ReadToEnd().Trim())
`
