//go:build windows

package windowsplatform

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type ownerProxyOption struct {
	Kind  uint32
	_     uint32 // Native union has 8-byte alignment in the supported x64 ABI.
	Value [8]byte
}

func (o *ownerProxyOption) stringPointer() *uint16     { return *(**uint16)(unsafe.Pointer(&o.Value[0])) }
func (o *ownerProxyOption) setStringPointer(p *uint16) { *(**uint16)(unsafe.Pointer(&o.Value[0])) = p }

type ownerProxyOptionList struct {
	Size         uint32
	Connection   uintptr
	Count, Error uint32
	Options      *ownerProxyOption
}

func ownerProxyCaller(sid string) error {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return errors.New("OWNER_PROXY_X64_REQUIRED")
	}
	if sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" {
		return errors.New("OWNER_PROXY_INTERACTIVE_OWNER_REQUIRED")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid.String() != sid {
		return errors.New("OWNER_PROXY_WRONG_PROCESS_OWNER")
	}
	const path = `Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		if value, _, readErr := key.GetIntegerValue("ProxySettingsPerUser"); readErr == nil && value == 0 {
			return errors.New("OWNER_PROXY_MACHINE_MANAGED")
		}
	} else if err != registry.ErrNotExist {
		return errors.New("OWNER_PROXY_MACHINE_POLICY_UNREADABLE")
	}
	return nil
}

func ReadOwnerSystemProxy(sid string) (OwnerProxyState, error) {
	if err := ownerProxyCaller(sid); err != nil {
		return OwnerProxyState{}, err
	}
	options := []ownerProxyOption{{Kind: 1}, {Kind: 2}, {Kind: 3}, {Kind: 4}}
	list := ownerProxyOptionList{Count: uint32(len(options)), Options: &options[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	size := list.Size
	api := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetQueryOptionW")
	ok, _, _ := api.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(options)
	free := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
	defer func() {
		for i := 1; i < len(options); i++ {
			if pointer := options[i].stringPointer(); pointer != nil {
				free.Call(uintptr(unsafe.Pointer(pointer)))
			}
		}
	}()
	if ok == 0 {
		return OwnerProxyState{}, fmt.Errorf("OWNER_PROXY_QUERY_FAILED_OPTION_%d", list.Error)
	}
	read := func(i int) string {
		if options[i].stringPointer() == nil {
			return ""
		}
		return windows.UTF16PtrToString(options[i].stringPointer())
	}
	return OwnerProxyState{Flags: *(*uint32)(unsafe.Pointer(&options[0].Value[0])), Server: read(1), Bypass: read(2), PAC: read(3)}, nil
}

// Compare the complete snapshot immediately before mutation. Foreign values
// must be refused by the caller; restoration is also conditional on this state.
func CompareSetOwnerSystemProxy(sid string, expected, desired OwnerProxyState) error {
	current, err := ReadOwnerSystemProxy(sid)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("OWNER_PROXY_CHANGED_PRESERVED")
	}
	values := []*uint16{nil, nil, nil}
	for i, text := range []string{desired.Server, desired.Bypass, desired.PAC} {
		values[i], err = windows.UTF16PtrFromString(text)
		if err != nil {
			return errors.New("OWNER_PROXY_VALUE_INVALID")
		}
	}
	options := []ownerProxyOption{{Kind: 1}, {Kind: 2}, {Kind: 3}, {Kind: 4}}
	*(*uint32)(unsafe.Pointer(&options[0].Value[0])) = desired.Flags
	for i, pointer := range values {
		options[i+1].setStringPointer(pointer)
	}
	list := ownerProxyOptionList{Count: uint32(len(options)), Options: &options[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	api := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")
	ok, _, _ := api.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(list.Size))
	runtime.KeepAlive(values)
	runtime.KeepAlive(options)
	if ok == 0 {
		return fmt.Errorf("OWNER_PROXY_SET_FAILED_OPTION_%d", list.Error)
	}
	// The supported WinINET notifications also refresh Chromium's registry-backed
	// system proxy provider. No Chrome page/restart, command line or user dialog.
	api.Call(0, 39, 0, 0)
	api.Call(0, 37, 0, 0)
	actual, err := ReadOwnerSystemProxy(sid)
	if err != nil {
		return err
	}
	if actual != desired {
		return errors.New("OWNER_PROXY_READBACK_MISMATCH")
	}
	return nil
}
