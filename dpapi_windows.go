//go:build windows

package main

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	size uint32
	data uintptr
}

func powershellExecutable() string { return "" }

func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty DPAPI blob")
	}
	in := dataBlob{size: uint32(len(data)), data: uintptr(unsafe.Pointer(&data[0]))}
	var out dataBlob
	r, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		if callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("CryptUnprotectData: %w", callErr)
		}
		return nil, errors.New("CryptUnprotectData failed")
	}
	defer procLocalFree.Call(out.data)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(out.data)), out.size)
	buf := make([]byte, len(raw))
	copy(buf, raw)
	return buf, nil
}
