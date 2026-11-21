//go:build windows

package windowsplatform

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

type DriverFiles struct {
	Directory    string `json:"directory"`
	DLLSHA256    string `json:"dll_sha256"`
	DriverSHA256 string `json:"driver_sha256"`
}
type divertDLL struct {
	dll                                                                      *windows.DLL
	open, recv, send, close, shutdown, checksum, getParam, setParam, compile *windows.Proc
}

func hashFile(path, want string) error {
	if len(want) != 64 {
		return errors.New("WinDivert requires configured SHA256 pins for DLL and driver")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(b)
	if !strings.EqualFold(want, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("WinDivert SHA256 mismatch: %s", filepath.Base(path))
	}
	return nil
}

// Official WinDivert DLL is unsigned; the SHA256-pinned kernel driver is signed.
func verifyAuthenticode(path string) error {
	type fileInfo struct {
		Size    uint32
		Path    *uint16
		Handle  uintptr
		Subject uintptr
	}
	type trustData struct {
		Size                  uint32
		Policy, SIP           uintptr
		UI, Revocation, Union uint32
		File                  uintptr
		State                 uint32
		StateData, URL        uintptr
		Flags, Context        uint32
		Settings              uintptr
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	f := fileInfo{Path: p}
	f.Size = uint32(unsafe.Sizeof(f))
	d := trustData{UI: 2, Union: 1, File: uintptr(unsafe.Pointer(&f)), Flags: 0x1010}
	d.Size = uint32(unsafe.Sizeof(d))
	guid := windows.GUID{Data1: 0x00aac56b, Data2: 0xcd44, Data3: 0x11d0, Data4: [8]byte{0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}
	proc := windows.NewLazySystemDLL("wintrust.dll").NewProc("WinVerifyTrust")
	result, _, _ := proc.Call(^uintptr(0), uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&d)))
	runtime.KeepAlive(p)
	runtime.KeepAlive(f)
	if int32(result) != 0 {
		return fmt.Errorf("WinDivert Authenticode validation failed: HRESULT 0x%08x", uint32(result))
	}
	return nil
}
func loadDivert(f DriverFiles) (*divertDLL, error) {
	if !filepath.IsAbs(f.Directory) {
		return nil, errors.New("WinDivert directory must be absolute")
	}
	dllPath := filepath.Join(f.Directory, "WinDivert.dll")
	driverPath := filepath.Join(f.Directory, "WinDivert64.sys")
	if e := hashFile(dllPath, f.DLLSHA256); e != nil {
		return nil, e
	}
	if e := hashFile(driverPath, f.DriverSHA256); e != nil {
		return nil, e
	}
	if e := verifyAuthenticode(driverPath); e != nil {
		return nil, e
	}
	handle, e := windows.LoadLibraryEx(dllPath, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
	if e != nil {
		return nil, fmt.Errorf("WinDivert loader: %w", e)
	}
	dll := &windows.DLL{Name: dllPath, Handle: handle}
	d := &divertDLL{dll: dll}
	slots := []struct {
		name string
		proc **windows.Proc
	}{{"WinDivertHelperCompileFilter", &d.compile}, {"WinDivertOpen", &d.open}, {"WinDivertRecv", &d.recv}, {"WinDivertSend", &d.send}, {"WinDivertClose", &d.close}, {"WinDivertShutdown", &d.shutdown}, {"WinDivertHelperCalcChecksums", &d.checksum}, {"WinDivertGetParam", &d.getParam}, {"WinDivertSetParam", &d.setParam}}
	for _, s := range slots {
		p, e := dll.FindProc(s.name)
		if e != nil {
			dll.Release()
			return nil, fmt.Errorf("WinDivert missing export %s", s.name)
		}
		*s.proc = p
	}
	return d, nil
}
