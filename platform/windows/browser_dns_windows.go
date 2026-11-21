//go:build windows

package windowsplatform

import (
	"context"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

func (b *WinDivertBackend) handleBrowserDNS(d *divertDLL, id ProcessIdentity, t Tuple, packet, payload []byte, a [80]byte, decision Decision) {
	b.evidence.RecordBytes(id, t, "captured", "", uint64(len(packet)))
	b.evidence.RecordPolicy(id, t, decision, "")
	if len(payload) < 12 || len(payload) > browserproxy.MaxDNSWire {
		b.evidence.RecordFailure(id, t, "BROWSER_DNS_QUERY_LIMIT", true)
		return
	}
	query := append([]byte(nil), payload...)
	template := udpReplyTemplate(packet)
	reply := func(wire []byte) {
		if len(wire) == 0 || b.ctx.Err() != nil {
			return
		}
		p, err := ReplyUDP(template, wire)
		if err != nil {
			return
		}
		address := a
		address[10] &^= 2
		// WinDivert treats local loopback packets as outbound in both directions.
		if t.Source.Addr().IsLoopback() && t.Destination.Addr().IsLoopback() {
			address[10] |= 2
		}
		if err = b.inject(d, p, address); err != nil {
			b.evidence.RecordFailure(id, t, "BROWSER_DNS_REPLY_INJECT_FAILED", true)
			return
		}
		b.evidence.RecordBytes(id, t, "reply", "", uint64(len(p)))
	}
	select {
	case b.dnsSlots <- struct{}{}:
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() { <-b.dnsSlots }()
			ctx, cancel := context.WithTimeout(b.ctx, 2*time.Second)
			defer cancel()
			wire, err := decision.DNSExchange(ctx, query)
			if err != nil {
				wire = browserproxy.DNSFailure(query)
				b.evidence.RecordFailure(id, t, "BROWSER_DNS_TRANSACTION_FAILED", true)
			}
			reply(wire)
		}()
	default:
		// No unbounded queue or packet-loop DNS I/O. No protected-query leak.
		b.evidence.RecordFailure(id, t, "BROWSER_DNS_WORKER_CAPACITY", true)
		reply(browserproxy.DNSFailure(query))
	}
}
