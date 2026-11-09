package windowsplatform

import (
	"bytes"
	"io"
	"net"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
)

// ReadDeferredHello retains original bytes (at most 32 KiB for two seconds),
// returning them even on incomplete/unsupported input. It never logs payload.
func ReadDeferredHello(c net.Conn) ([]byte, string, string) {
	deadline := time.Now().Add(localstrategy.HelloDeadline)
	c.SetReadDeadline(deadline)
	defer c.SetReadDeadline(time.Time{})
	data := make([]byte, 0, 4096)
	var progress deferredHelloProgress
	var buf [4096]byte
	emptyReads := 0
	for len(data) < localstrategy.MaxHelloBytes {
		if !time.Now().Before(deadline) {
			return data, "", "CLIENTHELLO_INCOMPLETE"
		}
		size := len(buf)
		if size > localstrategy.MaxHelloBytes-len(data) {
			size = localstrategy.MaxHelloBytes - len(data)
		}
		n, err := c.Read(buf[:size])
		data = append(data, buf[:n]...)
		if n > 0 {
			emptyReads = 0
			if progress.ready(data) {
				domain, reason, done := localstrategy.InspectHelloStream(data)
				if done {
					return data, domain, reason
				}
			}
		} else if err == nil {
			emptyReads++
			if emptyReads >= 100 {
				return data, "", "CLIENTHELLO_NO_PROGRESS"
			}
		}
		if err != nil {
			if err == io.EOF && len(data) == 0 {
				return nil, "", "CLIENT_CLOSED_BEFORE_DATA"
			}
			return data, "", "CLIENTHELLO_INCOMPLETE"
		}
	}
	return data, "", "REASSEMBLY_LIMIT"
}

// A stream Read is not a TCP segment: one valid hello may arrive one byte at a
// time. Bound bytes and elapsed time instead of successful Read calls. Inspect
// the full buffered hello only when its framing says it may be complete (or
// invalid), so tiny reads do not repeatedly allocate/scan the entire prefix.
// This cursor makes no routing decision and keeps no payload outside data.
type deferredHelloProgress struct {
	pos, remaining, handshakeBytes int
	header                         [4]byte
	headerN                        int
}

func (p *deferredHelloProgress) ready(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if data[0] != 22 {
		start := p.pos - 3
		if start < 0 {
			start = 0
		}
		p.pos = len(data)
		return bytes.Contains(data[start:], []byte("\r\n\r\n"))
	}
	for p.pos < len(data) {
		if p.remaining == 0 {
			if len(data)-p.pos < 5 {
				return false
			}
			h := data[p.pos : p.pos+5]
			n := int(h[3])<<8 | int(h[4])
			if h[0] != 22 || h[1] != 3 || h[2] < 1 || h[2] > 3 || n == 0 || n > 16384 || p.pos+5+n > localstrategy.MaxHelloBytes {
				return true // Let the shared inspector provide the exact reason.
			}
			p.pos += 5
			p.remaining = n
		}
		n := len(data) - p.pos
		if n > p.remaining {
			n = p.remaining
		}
		if p.headerN < len(p.header) {
			p.headerN += copy(p.header[p.headerN:], data[p.pos:p.pos+n])
		}
		p.handshakeBytes += n
		p.pos += n
		p.remaining -= n
		if p.headerN == len(p.header) {
			need := 4 + (int(p.header[1])<<16 | int(p.header[2])<<8 | int(p.header[3]))
			if p.header[0] != 1 || need < 38 || need+5 > localstrategy.MaxHelloBytes || p.handshakeBytes >= need {
				return true
			}
		}
	}
	return false
}

func ResolveDeferredDecision(initial Decision, domain, reason string) Decision {
	outer := ""
	if reason == "ECH_OUTER_SNI_ONLY" {
		outer = domain
		domain = ""
	}
	if initial.ResolveDomain == nil {
		initial.Block = true
		initial.Deferred = false
		initial.Policy.Action = flowpolicy.Block
		initial.Policy.Fallback = flowpolicy.FailBlock
		initial.Policy.Reason = "missing deferred resolver"
		return initial
	}
	d := initial.ResolveDomain(domain)
	d.OuterSNI = outer
	d.Deferred = false
	d.ResolveDomain = nil
	// Missing SNI is not a failed relay open. Chrome sends an ECH extension
	// even for GREASE; keep an explicit authenticated opaque-name route alive.
	// Other policies without such a route still fail closed.
	if domain == "" && d.BlockOnFailure && (d.Policy.Action != flowpolicy.RelayRequired || d.Route.Direct() || d.Route.Local()) {
		d.Block = true
	}
	if d.Block {
		d.Policy.Action = flowpolicy.Block
		if d.Policy.Fallback == flowpolicy.FailOpen {
			d.Policy.Fallback = flowpolicy.FailBlock
		}
	}
	return d
}
