package windowsplatform

import (
	"encoding/binary"
	"errors"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/routing"
	"time"
)

// GameUDPPacket changes ONLY the added decoy's payload/length/checksums. The
// original packet is passed separately, byte-for-byte, to the existing sender.
func GameUDPPacket(original, payload []byte) ([]byte, error) {
	_, _, err := ParseUDP(original)
	if err != nil || len(payload) < 1200 || len(payload) > gameudp.MaxPayload {
		return nil, errors.New("GAME_UDP_PACKET_INVALID")
	}
	h := int(original[0]&15) * 4
	q := make([]byte, h+8+len(payload))
	copy(q, original[:h+8])
	copy(q[h+8:], payload)
	binary.BigEndian.PutUint16(q[2:4], uint16(len(q)))
	binary.BigEndian.PutUint16(q[h+4:h+6], uint16(8+len(payload)))
	q[10], q[11], q[h+6], q[h+7] = 0, 0, 0, 0
	checksum := func(data []byte, seed uint32) uint16 {
		sum := seed
		for i := 0; i+1 < len(data); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		}
		if len(data)%2 != 0 {
			sum += uint32(data[len(data)-1]) << 8
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(q[10:12], checksum(q[:h], 0))
	seed := uint32(17 + len(q) - h)
	for i := 12; i < 20; i += 2 {
		seed += uint32(binary.BigEndian.Uint16(q[i : i+2]))
	}
	udp := checksum(q[h:], seed)
	if udp == 0 {
		udp = 65535
	}
	binary.BigEndian.PutUint16(q[h+6:h+8], udp)
	return q, nil
}

// The 5-packet generic DIRECT+ limit is untouched. This separate sender has
// K<=16/N<=4 plus engine-wide packet/byte admission. No queue or relay call.
func SendGameUDP(e *gameudp.Engine, flow *gameudp.Flow, id ProcessIdentity, tuple Tuple, p []byte, send func([]byte) error, ledger *EvidenceLedger, now time.Time) error {
	payload, k := e.Plan(flow, now)
	sent := 0
	for i := 0; i < k; i++ {
		q, err := GameUDPPacket(p, payload)
		if err == nil {
			err = send(q)
		}
		e.FakeSent(flow, len(q), err)
		if err != nil {
			break
		}
		sent++
		ledger.RecordBytes(id, tuple, "game_fake", "", uint64(len(q)))
	}
	if sent > 0 {
		ledger.RecordLocalResult(id, tuple, localstrategy.Result{Modified: true, Strategy: e.Evidence(flow).Variant.ID, Preset: "game-udp"}, uint64(len(p)))
	}
	err := send(p)
	if err == nil {
		e.Outgoing(flow, len(p)-int(p[0]&15)*4-8, now)
		ledger.RecordBytes(id, tuple, "direct", "", uint64(len(p)))
	}
	ledger.RecordGameUDP(id, tuple, e.Evidence(flow))
	return err
}
func (l *EvidenceLedger) RecordGameUDP(id ProcessIdentity, t Tuple, v gameudp.Evidence) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	flow, ok := l.lookupLocked(k)
	if !ok {
		return
	}
	if old := flow.GameUDP; old != nil && old.ID == v.ID && old.Sequence > v.Sequence {
		return
	}
	flow.GameUDP = &v
	l.storeLocked(k, flow)
}

// BindGameUDP makes one immutable per-tuple selection before allocating relay
// admission or sending the first packet. A cache update never changes this flow.
func BindGameUDP(d Decision, id ProcessIdentity, t Tuple, now time.Time) (Decision, *gameudp.Flow, error) {
	if d.GameUDP == nil {
		return d, nil, nil
	}
	f, err := d.GameUDP.OpenWithQuality(gameudp.Key{Network: d.Network, Application: id.Path, PID: id.PID, Birth: id.CreationTime, Source: t.Source, Destination: t.Destination}, now, d.GameQualityRelayID)
	if err != nil {
		d.GameUDP = nil
		return d, nil, err
	}
	evidence := d.GameUDP.Evidence(f)
	switch evidence.Stage {
	case gameudp.Local:
		d.Policy.Action = flowpolicy.DirectPlus
		d.Policy.Reason = "LOCAL_UDP probation; originals unchanged"
	case gameudp.Relay:
		qualified := evidence.Selection == gameudp.MeasuredRelaySelection
		if qualified {
			d.GameRelayID = d.GameQualityRelayID
		}
		d.Route = routing.Route{RelayID: d.GameRelayID}
		d.BlockOnFailure = true
		d.Policy.Action = flowpolicy.RelayRequired
		d.Policy.RelayID = d.GameRelayID
		d.Policy.Fallback = flowpolicy.Required
		d.Policy.Reason = "game DIRECT and local variants insufficient; authenticated relay trial"
		if qualified {
			d.Policy.Reason = gameudp.MeasuredRelaySelection
		}
		d.Flow.PinnedPolicy = &routing.Policy{Route: d.Route, BlockOnFailure: true, ExactRelay: qualified, RelayAddress: d.GameQualityRelayAddress}
	}
	return d, f, nil
}
