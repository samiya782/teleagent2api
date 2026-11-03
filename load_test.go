package main

import "testing"

func TestLoadDesktopState(t *testing.T) {
	state, err := loadDesktopState()
	if err != nil {
		t.Fatal(err)
	}
	if state.Token == "" || state.InstallID == "" || state.DeviceID == "" {
		t.Fatal("incomplete")
	}
	if len(state.Token) < 100 {
		t.Fatal("unexpected token length")
	}
}
