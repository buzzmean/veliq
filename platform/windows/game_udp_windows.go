//go:build windows

package windowsplatform

import (
	"os"
	"time"
	"unsafe"
)

func (b *WinDivertBackend) GameUDPGuardStatus() GameUDPGuardStatus {
	s := b.gameGuard.snapshot()
	p := b.gameProcessStatus()
	s.Conflict = s.Conflict || p.Conflict
	s.DriverAntiCheat = p.DriverAntiCheat
	s.VanguardDriverRunning = p.VanguardDriverRunning
	s.VanguardClientRunning = p.VanguardClientRunning
	s.FaceitDriverRunning = p.FaceitDriverRunning
	s.FaceitClientRunning = p.FaceitClientRunning
	s.AntiCheatQueryError = p.AntiCheatQueryError
	if p.Error != "" {
		s.Error = p.Error
		s.Ready = false
	}
	return s
}
func (b *WinDivertBackend) primeGameAllowed(packet []byte, a [80]byte) bool {
	g := &b.gameGuard
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready || g.error != "" || (len(g.foreign) > 0 && b.gameEval == nil) {
		return false
	}
	for _, h := range g.foreign {
		if len(h.filter) == 0 {
			h.matched = true
			return false
		}
		// The filter object came from the signed driver's REFLECT layer and this
		// packet/address was validated by ParseUDP. No process memory is queried.
		ok, _, _ := b.gameEval.Call(uintptr(unsafe.Pointer(&h.filter[0])), uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&a[0])))
		if ok != 0 {
			h.matched = true
			return false
		}
	}
	return true
}
func (b *WinDivertBackend) observeGameReflect() {
	defer b.wg.Done()
	d := b.proc()
	buf := make([]byte, 16*1024)
	for {
		var n uint32
		var a [80]byte
		ok, _, _ := d.recv.Call(b.gameReflect, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&a[0])))
		if ok == 0 {
			if b.ctx.Err() == nil {
				b.gameGuard.fail("UDP_REFLECT_OBSERVER_FAILED")
			}
			return
		}
		if n > uint32(len(buf)) {
			b.gameGuard.fail("UDP_REFLECT_FILTER_BOUND")
			continue
		}
		r, event, err := decodeGameReflect(a, buf[:n])
		if err != nil {
			b.gameGuard.fail("UDP_REFLECT_EVENT_INVALID")
			continue
		}
		b.gameGuard.event(r, event, uint32(os.Getpid()))
	}
}
func (b *WinDivertBackend) observeGameReplies() {
	defer b.wg.Done()
	b.directReplies.set(true, "PASSIVE_SNIFF", 0)
	d := b.proc()
	buf := make([]byte, 65535)
	for {
		var n uint32
		var a [80]byte
		ok, _, recvErr := d.recv.Call(b.gameReplies, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&a[0])))
		if ok == 0 {
			b.directReplies.set(false, "RECEIVE_FAILED", udpReplyNativeError(recvErr))
			if b.ctx.Err() == nil {
				b.gameGuard.fail("UDP_REPLY_OBSERVER_FAILED")
			} else {
				b.directReplies.set(false, "STOPPED", 0)
			}
			return
		}
		if n == 0 || n > uint32(len(buf)) {
			continue
		}
		tuple, payload, err := ParseUDP(buf[:n])
		if err != nil {
			continue
		}
		tuple.Source, tuple.Destination = tuple.Destination, tuple.Source
		if b.recordPassiveDirectReply(tuple, int(n), time.Now()) {
			continue
		}
		b.mu.Lock()
		f := b.flows[tuple]
		if f == nil || f.game == nil || f.decision.GameUDP == nil || !f.decision.Route.Direct() || f.decision.cs2LocalSocket || f.retired {
			b.mu.Unlock()
			continue
		}
		e, flow, id := f.decision.GameUDP, f.game, f.identity
		b.mu.Unlock()
		e.Reply(flow, len(payload), time.Now())
		b.evidence.RecordBytes(id, tuple, "direct_reply", "", uint64(n))
		b.evidence.RecordGameUDP(id, tuple, e.Evidence(flow))
	}
}
