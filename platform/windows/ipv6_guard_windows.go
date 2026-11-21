//go:build windows

package windowsplatform

import (
	"fmt"
	"os"
	"time"
	"unsafe"
)

// IPv6 is never redirected into the IPv4 relay. Attributable selected new flows
// are suppressed at NETWORK; other traffic is reinjected unchanged. Unsupported
// packets/unknown identity follow fail-open and are explicitly not leak-proof.
func (b *WinDivertBackend) guardIPv6(classify Classifier) {
	defer b.wg.Done()
	d := b.proc()
	buf := make([]byte, 65575)
	for {
		var n uint32
		var a [80]byte
		ok, _, err := d.recv.Call(b.ipv6, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&a[0])))
		if ok == 0 {
			if b.ctx.Err() == nil {
				b.fail(fmt.Errorf("IPv6 guard receive: %w", err))
			}
			return
		}
		if n == 0 || n > uint32(len(buf)) {
			continue
		}
		b.processIPv6(d, buf[:n], a, classify)
	}
}
func (b *WinDivertBackend) processIPv6(d *divertDLL, packet []byte, a [80]byte, classify Classifier) {
	b.ingress.ipv6.Add(1)
	b.policyMu.RLock()
	defer b.policyMu.RUnlock()
	n := uint32(len(packet))
	var ok uintptr
	var err error

	t, flags, parseErr := ParseIPv6Transport(packet)
	outbound := a[10]&2 != 0
	if parseErr == nil && !outbound {
		t.Source, t.Destination = t.Destination, t.Source
	}
	id := ProcessIdentity{}
	if parseErr == nil {
		b.associations.mu.RLock()
		association, known := b.associations.items[t]
		b.associations.mu.RUnlock()
		if known && IsCurrent(association.Identity) {
			id = association.Identity
		} else {
			var pid uint32
			var ownerErr error
			if t.Protocol == "tcp" {
				pid, ownerErr = resolveTCPOwner(t)
			} else {
				var raw []byte
				raw, ownerErr = queryUDPTable(23)
				if ownerErr == nil {
					var owners map[uint32]bool
					owners, ownerErr = udpOwners(raw, t.Source, true)
					if ownerErr == nil {
						pid, ownerErr = uniqueUDPOwner(owners)
					}
				}
			}
			if ownerErr == nil {
				id, _ = b.cache.Lookup(pid)
			}
		}
		decision, _ := ClassifyCapture(id, t, uint32(os.Getpid()), classify)
		if outbound {
			b.ingress.record("IPV6_NETWORK", id, t, decision, ingressDecision(id, decision, flags&0x12 == 2, false), "IPV6_OWNER_OR_SOCKET", "")
		}
		b.evidence.RecordBytes(id, t, "captured", "", uint64(n))
		b.evidence.RecordInitialPolicy(id, t, decision)
		if b.v6guard.Block(id, t, flags, decision, uint32(os.Getpid()), time.Now()) {
			b.hotBlocked()
			b.evidence.RecordHotAttach(id, t, b.hot.snapshot().Epoch, "HOT_ATTACH_IPV6_UNSUPPORTED", decision.Revision)
			if t.Protocol == "tcp" {
				if reset, e := hotTCPReset(packet, outbound); e == nil {
					address := a
					address[10] &= ^byte(2)
					d.checksum.Call(uintptr(unsafe.Pointer(&reset[0])), uintptr(len(reset)), uintptr(unsafe.Pointer(&address[0])), 0)
					var sent uint32
					d.send.Call(b.ipv6, uintptr(unsafe.Pointer(&reset[0])), uintptr(len(reset)), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(&address[0])))
				}
			}
			b.evidence.Record(id, t, "ipv6_blocked", "")
			b.drop(id, t)
			return
		}
		b.evidence.RecordBytes(id, t, "direct", "", uint64(n))
	}
	// No header or routing modification. NETWORK injection is supported.
	var sent uint32
	ok, _, err = d.send.Call(b.ipv6, uintptr(unsafe.Pointer(&packet[0])), uintptr(n), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(&a[0])))
	if ok == 0 && b.ctx.Err() == nil {
		b.fail(fmt.Errorf("IPv6 passthrough: %w", err))
		return
	}
}
