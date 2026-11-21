package windowsplatform

import (
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"time"
)

// LocalTCPBuffer retains at most 32 send contexts, each tied to its original
// WinDivert address. The native TCP table lock serializes Push/Flush/teardown.
type LocalTCPBuffer struct {
	hello localstrategy.HelloBuffer
	sends []func([]byte) error
}

func localMetadata(d Decision, id ProcessIdentity, t Tuple) localstrategy.Metadata {
	return localstrategy.Metadata{Domain: d.OriginDomain, TrustedOrigin: d.OriginDomain != "" && !d.OriginHintOnly, StrategyID: d.LocalStrategyID, Application: id.Path, Protocol: t.Protocol, Destination: t.Destination}
}
func (b *LocalTCPBuffer) Flush(d Decision, st *localstrategy.State, id ProcessIdentity, t Tuple, now time.Time, reason string, l *EvidenceLedger) error {
	if !b.hello.Pending() {
		return nil
	}
	return b.deliver(d, st, id, t, b.hello.Flush(st, reason, now), l)
}
func (b *LocalTCPBuffer) Expired(now time.Time) bool { return b.hello.Expired(now) }
func (b *LocalTCPBuffer) Push(d Decision, st *localstrategy.State, id ProcessIdentity, t Tuple, p []byte, send func([]byte) error, l *EvidenceLedger, now time.Time) error {
	eligible := st != nil && d.Local != nil && d.Route.Local() && id.PID != 0 && id.CreationTime != 0 && id.Path != ""
	// Preserve ordering on teardown and unsupported packet framing. Pure ACKs
	// may pass while data is held; their sequence space contains no application bytes.
	terminal := len(p) < 40 || p[0] != 0x45 || p[33]&0x27 != 0
	if !eligible || terminal {
		if err := b.Flush(d, st, id, t, now, "NO_TRANSFORM", l); err != nil {
			return err
		}
		return SendLocal(d, st, id, t, p, send, l)
	}
	accepted, out := d.Local.BufferTCP(p, st, &b.hello, localMetadata(d, id, t), now)
	if accepted {
		b.sends = append(b.sends, send)
	}
	if out != nil {
		if err := b.deliver(d, st, id, t, *out, l); err != nil {
			return err
		}
	}
	if accepted {
		if out == nil {
			l.RecordLocalInspection(id, t, b.hello.Inspection())
		}
		return nil
	}
	return SendLocal(d, st, id, t, p, send, l)
}
func (b *LocalTCPBuffer) deliver(d Decision, st *localstrategy.State, id ProcessIdentity, t Tuple, batch localstrategy.BufferedResult, l *EvidenceLedger) error {
	sends := b.sends
	b.sends = nil // no callback or payload retained after a decision
	r := batch.Result
	defer func() { l.RecordLocalInspection(id, t, r.Inspection) }()
	if r.Modified {
		sendStarted := time.Now()
		r.Inspection.OutputPacketsPlanned = len(r.Packets)
		for i, q := range r.Packets {
			if err := sends[r.PacketOrigins[i]](q); err != nil {
				r.Inspection.SendFailed = true
				r.Inspection.Reason = "TRANSFORM_SEND_FAILED"
				r.Inspection.Detail = "partial plan; original sequence space released unchanged"
				d.Local.Fail(st)
				r.Modified = false
				break
			}
			r.Inspection.OutputPacketsSent++
			if len(q) >= 20 && len(r.Inspection.SentPackets) < localstrategy.NativeTCPPacketLimit {
				item := localstrategy.DescribeSentPacket(q, batch.Originals[r.PacketOrigins[i]])
				item.Fake = r.FakeAt(i)
				r.Inspection.SentPackets = append(r.Inspection.SentPackets, item)
			}
		}
		r.Inspection.TransformSendMS = float64(time.Since(sendStarted)) / float64(time.Millisecond)
		if r.Modified {
			r.Inspection.TransformApplied = true
			total := 0
			for _, p := range batch.Originals {
				total += len(p)
			}
			d.Local.Commit(r, total)
			for i, p := range batch.Originals {
				if r.ModifiedOrigins[i] {
					item := r
					item.FakePackets = 0
					if r.FakePackets > 0 && r.PacketOrigins[0] == i {
						item.FakePackets = r.FakePackets
					}
					l.RecordLocalResult(id, t, item, uint64(len(p)))
				} else {
					l.RecordBytes(id, t, "direct", "", uint64(len(p)))
				}
			}
			return nil
		}
	}
	if d.BlockOnFailure && !st.Applied() {
		l.RecordPolicy(id, t, d, "LOCAL_STRATEGY_FAILED_BLOCK")
		for range batch.Originals {
			l.RecordDrop(id, t, "LOCAL_STRATEGY_FAILED_BLOCK", true)
		}
		return nil
	}
	var firstError error
	for i, p := range batch.Originals {
		if err := sends[i](p); err != nil {
			if firstError == nil {
				firstError = err
			}
		} else {
			l.RecordBytes(id, t, "direct", "", uint64(len(p)))
		}
	}
	return firstError
}
