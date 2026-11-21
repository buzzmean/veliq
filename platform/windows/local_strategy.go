package windowsplatform

import (
	"encoding/binary"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"time"
)

// SendLocal shares the existing NETWORK send path, with no additional handles.
// Any local engine failure falls back to the original packet. TCP sequence space
// is unchanged, so a partially sent split followed by the original is harmless
// TCP retransmission, not replay on a new connection.
func SendLocal(d Decision, state *localstrategy.State, id ProcessIdentity, tuple Tuple, p []byte, send func([]byte) error, evidence *EvidenceLedger) error {
	if d.Local == nil || !d.Route.Local() || id.PID == 0 || id.CreationTime == 0 || id.Path == "" {
		err := send(p)
		if err == nil {
			evidence.RecordBytes(id, tuple, "direct", "", uint64(len(p)))
		}
		return err
	}
	r := d.Local.Process(p, state, localstrategy.Metadata{Domain: d.OriginDomain, TrustedOrigin: d.OriginDomain != "", StrategyID: d.LocalStrategyID, Application: id.Path, Protocol: tuple.Protocol, Destination: tuple.Destination})
	defer evidence.RecordLocalInspection(id, tuple, r.Inspection)
	if r.Suppress {
		d.Local.Commit(r, len(p))
		evidence.RecordQuicFallback(id, tuple, r.Strategy, r.Preset)
		return nil
	}
	if r.Modified {
		sendStarted := time.Now()
		inspection := r.Inspection
		if inspection != nil {
			inspection.OutputPacketsPlanned = len(r.Packets)
		}
		for i, q := range r.Packets {
			if err := send(q); err != nil {
				if inspection != nil {
					inspection.SendFailed = true
					inspection.Reason = "TRANSFORM_SEND_FAILED"
					inspection.Detail = "full plan not committed; inspect partial output count"
				}
				d.Local.Fail(state)
				r = localstrategy.Result{Failed: true}
				break
			}
			if inspection != nil {
				inspection.OutputPacketsSent++
				if len(q) >= 20 && len(inspection.SentPackets) < localstrategy.NativeTCPPacketLimit {
					item := localstrategy.DescribeSentPacket(q, p)
					item.Fake = r.FakeAt(i)
					inspection.SentPackets = append(inspection.SentPackets, item)
				}
			}
		}
		if inspection != nil {
			inspection.TransformSendMS = float64(time.Since(sendStarted)) / float64(time.Millisecond)
		}
		if r.Modified {
			if inspection != nil {
				inspection.TransformApplied = true
			}
			d.Local.Commit(r, len(p))
			evidence.RecordLocalResult(id, tuple, r, uint64(len(p)))
			return nil
		}
	}
	if d.BlockOnFailure && state != nil && !state.Applied() {
		if payload, ok := packetPayloadForPolicy(p, tuple.Protocol); ok && payload > 0 {
			evidence.RecordPolicy(id, tuple, d, "LOCAL_STRATEGY_FAILED_BLOCK")
			evidence.RecordDrop(id, tuple, "LOCAL_STRATEGY_FAILED_BLOCK", true)
			return nil
		}
	}
	err := send(p)
	if err == nil {
		// The engine's flow-byte metric includes unchanged packets after a
		// successful transform. Capture counters distinguish actual modification
		// from native ACK/FIN/cutoff pass-through. Fail() clears Applied first.
		r.Active = state != nil && state.Applied()
		d.Local.Commit(r, len(p))
		evidence.RecordBytes(id, tuple, "direct", "", uint64(len(p)))
	}
	return err
}

// The engine computes UDP checksum before splitting. WinDivert's helper cannot
// compute a transport checksum from a fragment; preserve that valid checksum and
// mark it complete rather than allowing checksum-offload metadata from the input
// to describe a different (fragmented) packet. Only used on validated UDP path.
func LocalPacketAddress(p []byte, a [80]byte) [80]byte {
	if len(p) >= 20 && p[0] == 0x45 && p[9] == 17 && binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
		a[10] |= 0xa0
	}
	return a
}

func packetPayloadForPolicy(p []byte, protocol string) (int, bool) {
	if protocol == "tcp" {
		_, _, data, err := ParseTCP(p)
		return data, err == nil
	}
	_, data, err := ParseUDP(p)
	return len(data), err == nil
}
