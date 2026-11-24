//go:build windows

package windowsplatform

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/buzzmean/neexitlag/core/clubhealth"
	"golang.org/x/sys/windows"
)

var healthEvt = windows.NewLazySystemDLL("wevtapi.dll")
var healthEvtQuery = healthEvt.NewProc("EvtQuery")
var healthEvtNext = healthEvt.NewProc("EvtNext")
var healthEvtRender = healthEvt.NewProc("EvtRender")
var healthEvtClose = healthEvt.NewProc("EvtClose")

// Native XPath uses the Windows subset, with a separate bounded channel query.
// No subprocess, certutil, certificate/cache mutation or network probe.
func DiagnosticWindowsEvents(since time.Time) ([]clubhealth.Diagnostic, error) {
	var out []clubhealth.Diagnostic
	var failures []error
	for _, channel := range []string{"System", "Application"} {
		ch, _ := windows.UTF16PtrFromString(channel)
		xpath := fmt.Sprintf("*[System[(Level=1 or Level=2 or Level=3 or EventID=1074 or EventID=1001 or EventID=6008) and TimeCreated[timediff(@SystemTime) <= %d]]]", max(1, time.Since(since).Milliseconds()))
		q, _ := windows.UTF16PtrFromString(xpath)
		h, _, err := healthEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), 1|0x200)
		if h == 0 {
			failures = append(failures, err)
			continue
		}
		full := true
		for range 128 {
			var event uintptr
			var n uint32
			ok, _, err := healthEvtNext.Call(h, 1, uintptr(unsafe.Pointer(&event)), 100, 0, uintptr(unsafe.Pointer(&n)))
			if ok == 0 {
				full = false
				if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
					failures = append(failures, err)
				}
				break
			}
			raw, err := renderDiagnosticEvent(event)
			healthEvtClose.Call(event)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if e, ok := decodeDiagnosticEvent(channel, raw, NewDiscovery().Lookup); ok {
				out = append(out, e)
			}
		}
		healthEvtClose.Call(h)
		if full {
			failures = append(failures, windows.ERROR_MORE_DATA)
		}
	}
	return out, errors.Join(failures...)
}
func renderDiagnosticEvent(event uintptr) ([]byte, error) {
	var needed, properties uint32
	_, _, err := healthEvtRender.Call(0, event, 1, 0, 0, uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&properties)))
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, err
	}
	if needed == 0 || needed > 64*1024 {
		return nil, windows.ERROR_MORE_DATA
	}
	buf := make([]uint16, (int(needed)+1)/2)
	ok, _, err := healthEvtRender.Call(0, event, 1, uintptr(needed), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 {
		return nil, err
	}
	return []byte(windows.UTF16ToString(buf)), nil
}
