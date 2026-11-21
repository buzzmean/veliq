package windowsplatform

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/telemetry"
	"sort"
	"strings"
	"sync"
	"time"
)

type CaptureCounters struct {
	GameFakePackets    uint64 `json:"game_fake_packets"`
	GameFakeBytes      uint64 `json:"game_fake_bytes"`
	DirectReplyPackets uint64 `json:"direct_reply_packets"`
	DirectReplyBytes   uint64 `json:"direct_reply_bytes"`
	FakeTLS            uint64 `json:"fake_tls_packets"`
	QuicFallback       uint64 `json:"quic_fallback_packets"`
	DirectPlus         uint64 `json:"direct_plus_packets"`
	DirectPlusBytes    uint64 `json:"direct_plus_bytes"`
	IPv6Blocked        uint64 `json:"ipv6_blocked_packets"`
	CapturedBytes      uint64 `json:"captured_bytes"`
	RelayedBytes       uint64 `json:"relayed_bytes"`
	DirectBytes        uint64 `json:"direct_bytes"`
	ReplyBytes         uint64 `json:"relay_reply_bytes"`
	Captured           uint64 `json:"captured_packets"`
	Relayed            uint64 `json:"relayed_packets"`
	Direct             uint64 `json:"direct_packets"`
	Dropped            uint64 `json:"dropped_packets"`
	Reinject           uint64 `json:"reinject_packets"`
	LoopPrevented      uint64 `json:"loop_prevention_packets"`
	Replies            uint64 `json:"relay_reply_packets"`
}
type TCPAdmissionEvidence struct {
	State  string  `json:"state"`
	WaitMS float64 `json:"wait_ms"`
}

type FlowEvidence struct {
	LocalTCP        *localstrategy.TCPTrace `json:"local_tcp_packets,omitempty"`
	GameUDP         *gameudp.Evidence       `json:"game_udp,omitempty"`
	TCPAdmission    *TCPAdmissionEvidence   `json:"tcp_admission,omitempty"`
	HotAttach       *HotAttachFlow          `json:"hot_attach,omitempty"`
	FailureCause    string                  `json:"failure_cause,omitempty"`
	DropCause       string                  `json:"last_drop_cause,omitempty"`
	Lifecycle       string                  `json:"lifecycle,omitempty"`
	updateSeq       uint64
	recordKey       evidenceKey
	RelayOpen       *RelayOpenEvidence         `json:"relay_open,omitempty"`
	UDPQueue        *UDPQueueEvidence          `json:"udp_queue,omitempty"`
	UDPHealth       *routing.UDPHealthEvidence `json:"udp_health,omitempty"`
	UpstreamSource  string                     `json:"upstream_source,omitempty"`
	Policy          flowpolicy.Result          `json:"policy,omitempty"`
	Group           string                     `json:"process_group,omitempty"`
	Network         string                     `json:"network_fingerprint,omitempty"`
	FallbackReason  string                     `json:"fallback_reason,omitempty"`
	RequiredBlocked bool                       `json:"relay_required_blocked,omitempty"`
	pending         bool
	FlowID          uint64                    `json:"flow_id"`
	StartedAt       time.Time                 `json:"started_at"`
	LocalInspection *localstrategy.Inspection `json:"local_inspection,omitempty"`

	StrategyRevision string          `json:"strategy_revision,omitempty"`
	Preset           string          `json:"preset,omitempty"`
	Chain            string          `json:"chain,omitempty"`
	FakeTTL          uint8           `json:"fake_ttl,omitempty"`
	Active           bool            `json:"active,omitempty"`
	IdentityCurrent  bool            `json:"identity_current,omitempty"`
	Strategy         string          `json:"strategy,omitempty"`
	Domain           string          `json:"domain,omitempty"`
	Protocol         string          `json:"protocol"`
	IPVersion        string          `json:"ip_version"`
	PID              uint32          `json:"pid"`
	Executable       string          `json:"exe"`
	CreationTime     uint64          `json:"creation_time"`
	Source           string          `json:"source"`
	Destination      string          `json:"destination"`
	Route            string          `json:"selected_route"`
	RelayID          string          `json:"relay_id,omitempty"`
	Counters         CaptureCounters `json:"counters"`
	LastSeen         time.Time       `json:"last_seen"`
}

// EvidenceMarker scopes observations to one ledger lifetime without resetting
// other consumers' counters. A restart invalidates the opaque ledger ID.
type EvidenceMarker struct {
	LedgerID    string `json:"ledger_id"`
	AfterFlowID uint64 `json:"after_flow_id"`
	LostRecords uint64 `json:"lost_records"`
}
type EvidenceQuery struct {
	PID          uint32          `json:"pid"`
	CreationTime uint64          `json:"creation_time,omitempty"`
	Destination  string          `json:"destination,omitempty"`
	Source       string          `json:"source,omitempty"`
	Domain       string          `json:"domain,omitempty"`
	Since        *EvidenceMarker `json:"since,omitempty"`
}
type CaptureEvidence struct {
	Ingress      *CaptureIngressSnapshot `json:"ingress,omitempty"`
	Marker       EvidenceMarker          `json:"marker"`
	Since        *EvidenceMarker         `json:"since,omitempty"`
	EvidenceLost bool                    `json:"evidence_lost,omitempty"`

	Counters   CaptureCounters             `json:"counters"`
	Flows      []FlowEvidence              `json:"flows"`
	Truncated  bool                        `json:"truncated"`
	LocalDrops map[string]telemetry.Metric `json:"local_drops,omitempty"`
}
type evidenceKey struct {
	PID     uint32
	Started uint64
	Tuple   Tuple
}
type EvidenceLedger struct {
	nextUpdate, lostThroughUpdate uint64
	retired                       map[uint64]FlowEvidence
	retiredKeys                   map[evidenceKey]uint64
	ledgerID                      string
	nextFlowID, lostRecords       uint64
	mu                            sync.Mutex
	totals                        CaptureCounters
	flows                         map[evidenceKey]FlowEvidence
	aliases                       map[evidenceKey]evidenceKey
}

func NewEvidenceLedger() *EvidenceLedger {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return &EvidenceLedger{retired: map[uint64]FlowEvidence{}, retiredKeys: map[evidenceKey]uint64{}, ledgerID: hex.EncodeToString(nonce), flows: map[evidenceKey]FlowEvidence{}, aliases: map[evidenceKey]evidenceKey{}}
}
func increment(c *CaptureCounters, event string) {
	switch event {
	case "game_fake":
		c.GameFakePackets++
	case "direct_reply":
		c.DirectReplyPackets++
	case "quic_fallback":
		c.QuicFallback++
	case "local":
		c.DirectPlus++
	case "ipv6_blocked":
		c.IPv6Blocked++
	case "captured":
		c.Captured++
	case "relay":
		c.Relayed++
	case "direct", "direct_proxy":
		c.Direct++
	case "drop":
		c.Dropped++
	case "reinject":
		c.Reinject++
	case "self":
		c.LoopPrevented++
	case "reply":
		c.Replies++
	}
}

// Records metadata and counters only; packet payload never enters the ledger.
func (l *EvidenceLedger) Record(id ProcessIdentity, t Tuple, event, relay string) {
	l.RecordBytes(id, t, event, relay, 0)
}

// BeginFlow retires evidence for a reused tuple, without resetting lifetime totals.
// Call once when the capture backend creates a new flow, not for retransmitted SYNs.
func (l *EvidenceLedger) BeginFlow(id ProcessIdentity, t Tuple) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.keyLocked(id, t)
	if key.Tuple != t {
		return
	}
	l.retireLocked(key)
	if id.PID != 0 && id.CreationTime != 0 && id.Path != "" {
		l.createFlowLocked(key)
	}
}
func (l *EvidenceLedger) createFlowLocked(key evidenceKey) (FlowEvidence, bool) {
	l.roomLocked()
	l.nextFlowID++
	now := time.Now()
	v := FlowEvidence{pending: true, FlowID: l.nextFlowID, StartedAt: now, LastSeen: now}
	l.storeLocked(key, v)
	return v, true
}
func (l *EvidenceLedger) markerLocked() EvidenceMarker {
	return EvidenceMarker{l.ledgerID, l.nextFlowID, l.lostRecords}
}
func (l *EvidenceLedger) Marker() EvidenceMarker {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.markerLocked()
}
func (l *EvidenceLedger) RecordBytes(id ProcessIdentity, t Tuple, event, relay string, bytes uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordBytesLocked(id, t, event, relay, bytes)
}
func (l *EvidenceLedger) recordBytesLocked(id ProcessIdentity, t Tuple, event, relay string, bytes uint64) {
	increment(&l.totals, event)
	incrementBytes(&l.totals, event, bytes)
	if id.PID == 0 || id.CreationTime == 0 || id.Path == "" {
		return
	}
	key := l.keyLocked(id, t)
	v, exists := l.lookupLocked(key)
	if !exists && key.Tuple != t {
		l.lostRecords++
		l.nextUpdate++
		l.lostThroughUpdate = l.nextUpdate
		return
	}
	if !exists {
		var ok bool
		v, ok = l.createFlowLocked(key)
		if !ok {
			return
		}
	}
	v.pending = false
	v.Protocol = t.Protocol
	v.IPVersion = "IPv4"
	if t.Source.Addr().Is6() {
		v.IPVersion = "IPv6"
	}
	v.PID = id.PID
	v.Executable = id.Path
	v.CreationTime = id.CreationTime
	t = key.Tuple
	v.Source = t.Source.String()
	v.Destination = t.Destination.String()
	v.LastSeen = time.Now()
	increment(&v.Counters, event)
	incrementBytes(&v.Counters, event, bytes)
	if v.HotAttach != nil && (event == "relay" || event == "direct" || event == "reply") {
		h := *v.HotAttach
		h.State = "HOT_ATTACH_ROUTE_USED"
		v.HotAttach = &h
	}
	if event == "ipv6_blocked" {
		v.Route = "BLOCK_UNSUPPORTED_IPV6"
		v.RelayID = ""
	} else if (event == "relay" || event == "reply") && !v.RequiredBlocked && v.FailureCause == "" {
		v.Route = "RELAY"
		v.RelayID = relay
	} else if (event == "direct" || event == "direct_proxy") && v.Route != "DIRECT_PLUS" && !v.RequiredBlocked {
		// Native packets describe packet handling, not a new flow decision.
		// Only RecordLocal can establish successful DIRECT+ use.
		v.Route = "DIRECT"
		v.RelayID = ""
	}
	l.storeLocked(key, v)
}
func (l *EvidenceLedger) Snapshot(pid uint32) CaptureEvidence { return l.snapshot(pid, nil) }
func (l *EvidenceLedger) snapshot(pid uint32, active map[evidenceKey]bool) CaptureEvidence {
	return l.snapshotTarget(pid, "", active)
}
func (l *EvidenceLedger) snapshotTarget(pid uint32, destination string, active map[evidenceKey]bool) CaptureEvidence {
	out, _ := l.SnapshotQuery(EvidenceQuery{PID: pid, Destination: destination}, active)
	return out
}
func (l *EvidenceLedger) SnapshotQuery(q EvidenceQuery, active map[evidenceKey]bool) (CaptureEvidence, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := CaptureEvidence{Counters: l.totals, Flows: []FlowEvidence{}, Marker: l.markerLocked(), Since: q.Since}
	if q.Since != nil && (q.Since.LedgerID != l.ledgerID || q.Since.AfterFlowID > l.nextFlowID || q.Since.LostRecords > l.lostRecords) {
		return out, errors.New("invalid or expired capture marker; restart trial")
	}
	if q.Since != nil && q.Since.LostRecords != l.lostRecords {
		out.Truncated = true
		out.EvidenceLost = true
	}
	for k, v := range l.flows {
		if v.pending {
			continue
		}
		v.Active = active[k]
		if (q.PID == 0 || v.PID == q.PID) && (q.CreationTime == 0 || v.CreationTime == q.CreationTime) && (q.Destination == "" || v.Destination == q.Destination) && (q.Source == "" || v.Source == q.Source) && (q.Since == nil || v.FlowID > q.Since.AfterFlowID) && (q.Domain == "" || strings.EqualFold(v.Domain, q.Domain) || v.LocalInspection != nil && (strings.EqualFold(v.LocalInspection.Domain, q.Domain) || strings.EqualFold(v.LocalInspection.ObservedSNI, q.Domain))) {
			v = cloneFlow(v)
			out.Flows = append(out.Flows, v)
		}
	}
	sort.Slice(out.Flows, func(i, j int) bool {
		if out.Flows[i].Active != out.Flows[j].Active {
			return out.Flows[i].Active
		}
		return out.Flows[i].LastSeen.After(out.Flows[j].LastSeen)
	})
	if len(out.Flows) > 32 {
		out.Truncated = true
		out.Flows = out.Flows[:32]
	}
	for len(out.Flows) > 0 {
		raw, _ := json.Marshal(out)
		if len(raw) < 60000 {
			break
		}
		out.Truncated = true
		out.Flows = out.Flows[:len(out.Flows)-1]
	}
	return out, nil
}
func (l *EvidenceLedger) Cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.flows {
		if now.Sub(v.LastSeen) > 5*time.Minute {
			l.retireLocked(k)
		}
	}
}

// Explicitly excludes service transport even if a profile selects the service exe.
func ClassifyCapture(id ProcessIdentity, t Tuple, self uint32, classify Classifier) (Decision, bool) {
	if id.PID == self {
		return Decision{}, true
	}
	if id.PID == 0 || id.CreationTime == 0 || id.Path == "" {
		return Decision{}, false
	}
	return classify(id, t), false
}

func incrementBytes(c *CaptureCounters, event string, n uint64) {
	switch event {
	case "game_fake":
		c.GameFakeBytes += n
	case "local":
		c.DirectPlusBytes += n
	case "captured":
		c.CapturedBytes += n
	case "relay":
		c.RelayedBytes += n
	case "direct", "direct_proxy":
		c.DirectBytes += n
	case "direct_reply":
		c.DirectReplyBytes += n
	case "reply":
		c.ReplyBytes += n
	}
}

// AddBytes records stream payload only. TCP read boundaries are not packets.
func (l *EvidenceLedger) AddBytes(id ProcessIdentity, t Tuple, event, relay string, n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	incrementBytes(&l.totals, event, n)
	key := l.keyLocked(id, t)
	if v, ok := l.lookupLocked(key); ok {
		incrementBytes(&v.Counters, event, n)
		v.LastSeen = time.Now()
		l.storeLocked(key, v)
	}
}

// RecordLocal counts only transformed original packets/bytes after ALL output
// packets have been sent successfully. Metadata and counters publish atomically.
// These are not a guessed VPS saving or a proof of application-level success.
func (l *EvidenceLedger) RecordLocal(id ProcessIdentity, t Tuple, strategy, domain string, n uint64) {
	l.RecordLocalResult(id, t, localstrategy.Result{Strategy: strategy, Domain: domain}, n)
}
func (l *EvidenceLedger) RecordLocalResult(id ProcessIdentity, t Tuple, r localstrategy.Result, n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordBytesLocked(id, t, "local", "", n)
	key := l.keyLocked(id, t)
	v, ok := l.lookupLocked(key)
	if ok {
		v.Route = "DIRECT_PLUS"
		if v.HotAttach != nil {
			h := *v.HotAttach
			h.State = "HOT_ATTACH_TRANSFORM_APPLIED"
			v.HotAttach = &h
		}
		v.RelayID = ""
		v.Strategy = r.Strategy
		v.Domain = r.Domain
		v.Preset = r.Preset
		v.StrategyRevision = r.Revision
		v.Chain = r.Chain
		if r.FakePackets > 0 {
			v.FakeTTL = r.FakeTTL
			v.Counters.FakeTLS += r.FakePackets
			l.totals.FakeTLS += r.FakePackets
		}
		l.storeLocked(key, v)
	}
}

func (l *EvidenceLedger) RecordQuicFallback(id ProcessIdentity, t Tuple, strategy, preset string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordBytesLocked(id, t, "quic_fallback", "", 0)
	k := l.keyLocked(id, t)
	if v, ok := l.lookupLocked(k); ok {
		v.Route = "DIRECT_PLUS"
		if v.HotAttach != nil {
			h := *v.HotAttach
			h.State = "HOT_ATTACH_TRANSFORM_APPLIED"
			v.HotAttach = &h
		}
		v.RelayID = ""
		v.Strategy = strategy
		v.Preset = preset
		v.Chain = "HTTP/3/QUIC → TCP fallback"
		l.storeLocked(k, v)
	}
}

// Passive domain attribution is metadata only and never changes the route.
func (l *EvidenceLedger) RecordDomain(id ProcessIdentity, t Tuple, domain string) {
	if domain == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	if v, ok := l.lookupLocked(k); ok && v.Domain == "" {
		v.Domain = domain
		l.storeLocked(k, v)
	}
}

// Passive first-payload diagnostics never change route, chain or wire counters.
func (l *EvidenceLedger) RecordLocalInspection(id ProcessIdentity, t Tuple, d *localstrategy.Inspection) {
	if d == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	if v, ok := l.lookupLocked(k); ok && (v.LocalInspection == nil || v.LocalInspection.Reason == "DELEGATED_TCP_OWNER_NOT_CONFIRMED" || d.SegmentsSeen > 0 && (v.LocalInspection.Reason == "REASSEMBLY_STARTED" || v.LocalInspection.Reason == "REASSEMBLY_WAITING" || v.LocalInspection.Reason == "REASSEMBLY_OUT_OF_ORDER")) {
		copy := *d
		v.LocalInspection = &copy
		l.storeLocked(k, v)
	}
}

func (l *EvidenceLedger) keyLocked(id ProcessIdentity, t Tuple) evidenceKey {
	k := evidenceKey{id.PID, id.CreationTime, t}
	if a, ok := l.aliases[k]; ok {
		return a
	}
	return k
}

// BindUpstream is restricted to an internally-created socket before its SYN.
// Its capture events belong to the original application flow, not service egress.
func (l *EvidenceLedger) BindUpstream(id ProcessIdentity, upstream, original Tuple) bool {
	if upstream.Protocol != "tcp" || original.Protocol != "tcp" || upstream.Destination != original.Destination || upstream.Source == original.Source || !upstream.Source.IsValid() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.aliases) >= 1024 {
		return false
	}
	key := evidenceKey{id.PID, id.CreationTime, original}
	if _, ok := l.lookupLocked(key); !ok {
		return false
	}
	v, _ := l.lookupLocked(key)
	v.UpstreamSource = upstream.Source.String()
	l.storeLocked(key, v)
	l.aliases[evidenceKey{id.PID, id.CreationTime, upstream}] = key
	return true
}
func (l *EvidenceLedger) UnbindUpstream(id ProcessIdentity, t Tuple) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.aliases, evidenceKey{id.PID, id.CreationTime, t})
}
func (l *EvidenceLedger) RecordPolicy(id ProcessIdentity, t Tuple, d Decision, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.keyLocked(id, t)
	v, ok := l.lookupLocked(key)
	if !ok {
		return
	}
	v.Policy = d.Policy
	v.Group = d.Group
	v.Network = d.Network
	if reason != "" {
		v.FallbackReason = reason
	}
	l.storeLocked(key, v)
}
func (l *EvidenceLedger) pruneAliases(keep func(Tuple) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.aliases {
		if !keep(k.Tuple) {
			delete(l.aliases, k)
		}
	}
}

func (l *EvidenceLedger) RecordUpstreamOpened(id ProcessIdentity, t Tuple, r routing.Route) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.keyLocked(id, t)
	if v, ok := l.lookupLocked(key); ok {
		if v.Route != "DIRECT_PLUS" {
			v.Route = string(r.Type())
			if r.Local() {
				v.Route = "DIRECT"
			}
			v.RelayID = r.RelayID
		}
		l.storeLocked(key, v)
	}
}

func (l *EvidenceLedger) RecordInitialPolicy(id ProcessIdentity, t Tuple, d Decision) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.keyLocked(id, t)
	if v, ok := l.lookupLocked(key); ok && v.Policy.Source == "" {
		v.Policy = d.Policy
		v.Group = d.Group
		v.Network = d.Network
		l.storeLocked(key, v)
	}
}

// RecordUDPHealth copies metadata only. Publishing a timeout/state change never
// manufactures packets/bytes or changes the flow's actual packet counters.
func (l *EvidenceLedger) RecordUDPHealth(id ProcessIdentity, t Tuple, health routing.UDPHealthEvidence) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.keyLocked(id, t)
	v, ok := l.lookupLocked(key)
	if !ok {
		return
	}
	v.UDPHealth = &health
	if health.State == routing.FlowRelayFallback {
		v.FallbackReason = health.Reason
	}
	l.storeLocked(key, v)
}
