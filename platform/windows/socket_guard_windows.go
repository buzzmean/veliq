//go:build windows

package windowsplatform

import (
	"fmt"
	"unsafe"
)

// SOCKET is sniff/receive-only: WinDivert cannot reinject socket events.
// Native process identity arrives before the corresponding network SYN.
func (b *WinDivertBackend) socketGuard(_ Classifier) {
	defer b.wg.Done()
	d := b.proc()
	for {
		var a [80]byte
		ok, _, err := d.recv.Call(b.socket, 0, 0, 0, uintptr(unsafe.Pointer(&a[0])))
		if ok == 0 {
			if b.ctx.Err() == nil {
				b.fail(fmt.Errorf("socket identity observer: %w", err))
			}
			return
		}
		b.ingress.socket.Add(1)
		pid, t, decodeErr := DecodeSocketEvent(a)
		id, lookupErr := b.cache.Lookup(pid)
		code := ""
		if decodeErr != nil {
			code = "SOCKET_EVENT_DECODE_FAILED"
		} else if lookupErr != nil {
			code = "PROCESS_LOOKUP_FAILED"
			id.PID = pid
		}
		b.ingress.record("SOCKET_CONNECT", id, t, Decision{}, "OWNER_EVENT_OBSERVED", "SOCKET_EVENT", code)
		if decodeErr == nil && lookupErr == nil && t.Protocol == "tcp" && t.Source.Port() != 0 && !t.Source.Addr().IsUnspecified() {
			b.associations.Put(Association{Identity: id, Tuple: t})
		}
	}
}
