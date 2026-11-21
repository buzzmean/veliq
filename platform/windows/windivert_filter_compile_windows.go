//go:build windows

package windowsplatform

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Compile AND serialize: exercises the parser, expression/instruction limits
// and object emitter, without opening any WinDivert/kernel handles. WinDivert
// 2.2.2 permits at most 256 filter instructions; this buffer is ample for its
// serialized object. The DLL reports a bounded diagnostic and byte offset.
func compileDivertFilter(proc *windows.Proc, filter string, layer uintptr) error {
	s, err := windows.BytePtrFromString(filter)
	if err != nil {
		return fmt.Errorf("WINDIVERT_FILTER_COMPILE_FAILED layer=%d length=%d: %w", layer, len(filter), err)
	}
	object := make([]byte, 65536)
	var message *byte
	var position uint32
	ok, _, callErr := proc.Call(uintptr(unsafe.Pointer(s)), layer,
		uintptr(unsafe.Pointer(&object[0])), uintptr(len(object)),
		uintptr(unsafe.Pointer(&message)), uintptr(unsafe.Pointer(&position)))
	runtime.KeepAlive(s)
	runtime.KeepAlive(object)
	if ok != 0 {
		return nil
	}
	reason := "DLL did not return a diagnostic"
	if message != nil {
		reason = windows.BytePtrToString(message)
	}
	// Filters contain only packet metadata, never tokens or identity material.
	return fmt.Errorf("WINDIVERT_FILTER_COMPILE_FAILED layer=%d offset=%d length=%d reason=%q win32=%v filter=%q", layer, position, len(filter), reason, callErr, filter)
}
