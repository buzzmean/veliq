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
	d := b.proc()
	buf := make([]byte, 65535)
	for {
		var n uint32
		var a [80]byte
		ok, _, _ := d.recv.Call(b.gameReplies, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&a[0])))
		if ok == 0 {
			if b.ctx.Err() == nil {
				b.gameGuard.fail("UDP_REPLY_OBSERVER_FAILED")
			}
			return
		}
		if n == 0 || n > uint32(len(buf)) {
			continue
		}
		b.recordNativeUDPReply(buf[:n], time.Now())
	}
}

// The existing inbound observer also sees ordinary native DIRECT/DIRECT+ UDP.
// Attribute only the exact reverse tuple of a current native capture flow.
// Adaptive/proxied replies are counted by forward(), never a second time here.
func (b *WinDivertBackend) recordNativeUDPReply(packet []byte, now time.Time) {
	tuple, payload, err := ParseUDP(packet)
	if err != nil {
		return
	}
	tuple.Source, tuple.Destination = tuple.Destination, tuple.Source
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.flows[tuple]
	if f == nil || f.retired || f.decision.Block || !f.decision.Route.Direct() || f.decision.ProbeDirect || f.datagram != nil || f.identity.PID == 0 || f.identity.CreationTime == 0 || f.identity.Path == "" {
		return
	}
	f.lastSeen = now
	b.evidence.RecordBytes(f.identity, tuple, "direct_reply", "", uint64(len(packet)))
	if f.game != nil && f.decision.GameUDP != nil {
		e := f.decision.GameUDP
		e.Reply(f.game, len(payload), now)
		b.evidence.RecordGameUDP(f.identity, tuple, e.Evidence(f.game))
	}
}
