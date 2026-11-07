// Package gameudp implements a bounded per-game UDP transport ladder and first-flight decoy.
// It has no relay, protocol decryption, process access or packet capture code.
package gameudp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/buzzmean/neexitlag/core/routing"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	MaxRepeats            = 16
	MaxCutoff             = 4
	MaxPayload            = 1400
	MaxPerFlow            = MaxRepeats * MaxCutoff
	MaxFlows              = 128
	MaxNetworks           = 16
	MaxFakePerSecond      = 256
	MaxFakeBytesPerSecond = MaxFakePerSecond * MaxPayload
	Probation             = 6 * time.Second
	ConfirmationSpan      = 2 * time.Second
	Liveness              = 5 * time.Second
	LearnTTL              = 6 * time.Hour
)

type Variant struct {
	ID      string `json:"id"`
	Repeats int    `json:"repeats"`
	Cutoff  int    `json:"cutoff"`
	Size    int    `json:"payload_size"`
	First   byte   `json:"first_byte"`
}

func Variants() []Variant {
	return []Variant{
		{"quic-v1-c8-k12-n2", 12, 2, 1250, 0xc8},
		{"quic-v1-c8-k6-n3", 6, 3, 1250, 0xc8},
		{"quic-v1-c8-k10-n3", 10, 3, 1250, 0xc8},
		{"quic-v1-c8-k14-n3", 14, 3, 1250, 0xc8},
		{"quic-v1-c8-k12-n4", 12, 4, 1250, 0xc8},
		{"quic-v1-c0-k10-n2", 10, 2, 1280, 0xc0},
	}
}
func (v Variant) Validate() error {
	if v.Repeats < 1 || v.Repeats > MaxRepeats || v.Cutoff < 1 || v.Cutoff > MaxCutoff || v.Size < 1200 || v.Size > MaxPayload || (v.First != 0xc8 && v.First != 0xc0) {
		return errors.New("GAME_UDP_VARIANT_INVALID")
	}
	return nil
}

// Generate uses an independent random DCID, SCID and body for every flow. This
// is an intentionally unauthenticated QUIC-shaped datagram, not a QUIC session.
func Generate(v Variant, random io.Reader) ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	p := make([]byte, v.Size)
	if _, err := io.ReadFull(random, p); err != nil {
		return nil, errors.New("GAME_UDP_RANDOM_UNAVAILABLE")
	}
	p[0] = v.First
	binary.BigEndian.PutUint32(p[1:5], 1)
	p[5] = 8
	p[14] = 8
	p[23] = 0
	binary.BigEndian.PutUint16(p[24:26], 0x4000|uint16(len(p)-26))
	return p, nil
}
func Canonical(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }
func Eligible(application, selected, protocol string, dst netip.AddrPort) bool {
	return selected != "" && Canonical(application) == Canonical(selected) && protocol == "udp" && dst.IsValid() && dst.Addr().Is4() && dst.Port() >= 1024 && !routing.LocalDestination(dst.Addr())
}

type Key struct {
	Network             string
	Application         string
	PID                 uint32
	Birth               uint64
	Source, Destination netip.AddrPort
}

const (
	Direct = "DIRECT"
	Local  = "LOCAL_UDP"
	Relay  = "RELAY"
)

type Evidence struct {
	FakeTTL       uint8     `json:"fake_ttl,omitempty"`
	Selection     string    `json:"selection_reason"`
	Sequence      uint64    `json:"update_seq"`
	Stage         string    `json:"stage"`
	ID            uint64    `json:"flow_id"`
	Network       string    `json:"network_fingerprint"`
	PID           uint32    `json:"pid"`
	Birth         uint64    `json:"creation_time"`
	Application   string    `json:"exe"`
	Source        string    `json:"source"`
	Destination   string    `json:"destination"`
	Variant       Variant   `json:"variant"`
	Started       time.Time `json:"started_at"`
	LastOutgoing  time.Time `json:"last_outgoing"`
	FirstReply    time.Time `json:"first_reply"`
	LastReply     time.Time `json:"last_reply"`
	Outgoing      uint64    `json:"outgoing_packets"`
	OutgoingBytes uint64    `json:"outgoing_bytes"`
	Replies       uint64    `json:"inbound_packets"`
	ReplyBytes    uint64    `json:"inbound_bytes"`
	Fakes         uint64    `json:"fake_packets"`
	FakeBytes     uint64    `json:"fake_bytes"`
	FakeErrors    uint64    `json:"fake_send_errors"`
	RateLimited   uint64    `json:"rate_limited_packets"`
	State         string    `json:"state"`
	Reason        string    `json:"reason"`
}
type cadenceBucket struct {
	second            int64
	replies, outgoing uint64
}
type Flow struct {
	primer      bool
	cadence     [8]cadenceBucket
	degradedAt  time.Time
	engine      *Engine
	key         Key
	e           Evidence
	payload     []byte
	ordinal     int
	generation  uint64
	bucketFirst int64
	bucketLast  int64
	buckets     int
	learned     bool
	failed      bool
	last        time.Time
}
type Learning struct {
	LocalOnly   bool      `json:"local_only,omitempty"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Stage       string    `json:"stage,omitempty"`
	Exhausted   bool      `json:"exhausted,omitempty"`
	Network     string    `json:"network"`
	Application string    `json:"application"`
	Index       int       `json:"index"`
	Tried       int       `json:"tried"`
	Confirmed   bool      `json:"confirmed"`
	Expires     time.Time `json:"expires"`
}
type Snapshot struct {
	Primer        *Primer    `json:"primer,omitempty"`
	LocalOnly     bool       `json:"local_only"`
	InitialPolicy string     `json:"initial_policy"`
	Enabled       bool       `json:"enabled"`
	Application   string     `json:"application"`
	Generation    uint64     `json:"generation"`
	Reason        string     `json:"reason"`
	Flows         []Evidence `json:"flows"`
	Learning      []Learning `json:"learning"`
	Truncated     bool       `json:"truncated"`
	Lost          uint64     `json:"lost"`
}
type Engine struct {
	primer                     *Primer
	mu                         sync.Mutex
	ladder                     bool
	localOnly                  bool
	startLocal                 bool
	shared                     *Budget
	application                string
	network                    string
	enabled                    bool
	generation, next, lost     uint64
	reason                     string
	flows                      map[uint64]*Flow
	learning                   map[string]Learning
	revision                   uint64
	budgetAt                   time.Time
	budgetPackets, budgetBytes int
}

func New() *Engine {
	return &Engine{enabled: true, generation: 1, flows: map[uint64]*Flow{}, learning: map[string]Learning{}, reason: "GAME_NOT_DISCOVERED"}
}

// NewLadder starts every unmeasured network/game DIRECT. Route/variant changes
// apply to NEXT flows only; the caller owns authenticated relay transport.
func NewLadder(b *Budget) *Engine { e := New(); e.ladder = true; e.shared = b; return e }

// SetStartLocal affects only subsequent Open calls; existing tuples keep their
// selected stage and first-flight cutoff. Exact confirmed DIRECT endpoints win.
func (e *Engine) SetStartLocal(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.startLocal = enabled
}

// SetLocalOnly restricts future flows to DIRECT/local trials. Existing routes
// stay pinned; their observations cannot teach a different policy generation.
func (e *Engine) SetLocalOnly(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.localOnly != enabled {
		e.generation++
	}
	e.localOnly = enabled
}

func (e *Engine) Configure(application string, enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if Canonical(e.application) != Canonical(application) || e.enabled != enabled {
		e.generation++
	}
	e.application = application
	e.enabled = enabled
}
func (e *Engine) SetReason(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if (e.reason == "") != (reason == "") {
		e.generation++
	}
	e.reason = reason
}
func (e *Engine) Application() string   { e.mu.Lock(); defer e.mu.Unlock(); return e.application }
func (e *Engine) Enabled() bool         { e.mu.Lock(); defer e.mu.Unlock(); return e.enabled }
func endpointKey(n, a, d string) string { return learnKey(n, a) + "\x00" + d }
func learnKey(n, a string) string       { return n + "\x00" + Canonical(a) }
func (e *Engine) trialKey(k Key) string {
	if e.localOnly {
		return endpointKey(k.Network, k.Application, k.Destination.String())
	}
	return learnKey(k.Network, k.Application)
}

func (e *Engine) Open(k Key, now time.Time) (*Flow, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.enabled || e.reason != "" || (e.network != "" && e.network != k.Network) || len(k.Network) != 64 || k.PID == 0 || k.Birth == 0 || !Eligible(k.Application, e.application, "udp", k.Destination) {
		return nil, errors.New("GAME_UDP_SCOPE_UNAVAILABLE")
	}
	e.cleanup(now)
	if len(e.flows) >= MaxFlows {
		return nil, errors.New("GAME_UDP_FLOW_CAPACITY")
	}
	if e.primer != nil {
		return e.openPrimer(k, now)
	}
	cache := e.learning[e.trialKey(k)]
	// Results from another route policy cannot grant relay or carry exhaustion
	// across a policy switch. Confirmed DIRECT endpoints remain safe to reuse.
	if cache.LocalOnly != e.localOnly {
		cache = Learning{}
	}
	// Legacy application-wide DIRECT results are not proof of this endpoint.
	if e.ladder && e.startLocal && cache.Stage == Direct {
		cache = Learning{}
	}
	if e.ladder {
		if direct := e.learning[endpointKey(k.Network, k.Application, k.Destination.String())]; direct.Confirmed && direct.Stage == Direct && now.Before(direct.Expires) {
			cache = direct
		}
	}
	index := 0
	stage := Local
	selection := "LOCAL_FIRST_UNCONFIRMED_ENDPOINT"
	if e.ladder && !e.startLocal {
		stage = Direct
		selection = "DEFAULT_DIRECT_TRIAL"
	}
	if now.Before(cache.Expires) {
		index = cache.Index
		if e.ladder && cache.Stage != "" {
			stage = cache.Stage
		}
		selection = "LEARNED_NETWORK_TRIAL"
		if stage == Direct && cache.Confirmed && cache.Endpoint == k.Destination.String() {
			selection = "CONFIRMED_DIRECT_ENDPOINT"
		}
		if cache.Exhausted || (!e.ladder && cache.Tried >= len(Variants()) && !cache.Confirmed) {
			if e.localOnly {
				return nil, errors.New("GAME_UDP_LOCAL_ONLY_EXHAUSTED")
			}
			return nil, errors.New("GAME_UDP_VARIANTS_EXHAUSTED")
		}
	}
	if e.localOnly && stage == Relay {
		return nil, errors.New("GAME_UDP_LOCAL_ONLY_EXHAUSTED")
	}
	v := Variants()[index]
	if stage != Local {
		v = Variant{}
	}
	var p []byte
	if stage == Local {
		var err error
		p, err = Generate(v, nil)
		if err != nil {
			return nil, err
		}
	}
	e.next++
	f := &Flow{engine: e, key: k, generation: e.generation, payload: p, last: now, e: Evidence{Selection: selection, Stage: stage, ID: e.next, Network: k.Network, PID: k.PID, Birth: k.Birth, Application: k.Application, Source: k.Source.String(), Destination: k.Destination.String(), Variant: v, Started: now, State: "PROBATION", Reason: "SUSTAINED_REPLY_NOT_OBSERVED"}}
	e.flows[f.e.ID] = f
	return f, nil
}

// Plan advances the input cutoff even if a decoy fails. Existing flows never
// restart their first flight after settings/learning/network changes.
func (e *Engine) Plan(f *Flow, now time.Time) ([]byte, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil || f.engine != e {
		return nil, 0
	}
	f.last = now
	f.e.Sequence++
	f.ordinal++
	if f.e.Stage != Local || !e.enabled || e.reason != "" || f.generation != e.generation || f.ordinal > f.e.Variant.Cutoff || f.primer && !e.localOnly {
		return nil, 0
	}
	k := f.e.Variant.Repeats
	if e.budgetAt.IsZero() || now.Sub(e.budgetAt) >= time.Second {
		e.budgetAt = now
		e.budgetPackets = 0
		e.budgetBytes = 0
	}
	if e.budgetPackets+k > MaxFakePerSecond || e.budgetBytes+k*(len(f.payload)+68) > MaxFakeBytesPerSecond {
		f.e.RateLimited += uint64(k)
		f.e.Reason = "DECOY_RATE_LIMITED_ORIGINAL_PASSTHROUGH"
		return nil, 0
	}
	if e.shared != nil && !e.shared.take(k, k*(len(f.payload)+68), now) {
		f.e.RateLimited += uint64(k)
		f.e.Reason = "GLOBAL_DECOY_RATE_LIMITED"
		return nil, 0
	}
	e.budgetPackets += k
	e.budgetBytes += k * (len(f.payload) + 68)
	// Caller treats payload as immutable; no kernel packet references are retained.
	return f.payload, k
}
func (e *Engine) FakeSent(f *Flow, n int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil || f.engine != e {
		return
	}
	f.e.Sequence++
	if err != nil {
		f.e.FakeErrors++
		f.e.Reason = "DECOY_SEND_FAILED_ORIGINAL_PASSTHROUGH"
		return
	}
	f.e.Fakes++
	f.e.FakeBytes += uint64(n)
}
func (e *Engine) Outgoing(f *Flow, n int, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil || f.engine != e {
		return
	}
	f.e.Sequence++
	if !f.e.LastOutgoing.IsZero() && now.Sub(f.e.LastOutgoing) > 2*time.Second {
		f.degradedAt = now
	}
	b := &f.cadence[uint64(now.Unix())%8]
	if b.second != now.Unix() {
		*b = cadenceBucket{second: now.Unix()}
	}
	b.outgoing++
	f.e.Outgoing++
	f.e.OutgoingBytes += uint64(n)
	f.e.LastOutgoing = now
	f.last = now
}
func (e *Engine) Reply(f *Flow, n int, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil || f.engine != e {
		return
	}
	f.e.Sequence++
	b := &f.cadence[uint64(now.Unix())%8]
	if b.second != now.Unix() {
		*b = cadenceBucket{second: now.Unix()}
	}
	b.replies++
	f.e.Replies++
	f.e.ReplyBytes += uint64(n)
	f.e.LastReply = now
	f.last = now
	if f.e.FirstReply.IsZero() {
		f.e.FirstReply = now
		f.bucketFirst = now.Unix()
		f.bucketLast = now.Unix()
		f.buckets = 1
	} else if now.Unix() > f.bucketLast {
		f.bucketLast = now.Unix()
		f.buckets++
	}
}
func (e *Engine) Tick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, f := range e.flows {
		e.health(f, now)
	}
	e.cleanup(now)
}
func (e *Engine) health(f *Flow, now time.Time) {
	if f.failed || f.generation != e.generation || !e.enabled || e.reason != "" || f.e.Outgoing < 6 || now.Sub(f.e.LastOutgoing) > 2*time.Second {
		return
	}
	replies, outgoing, buckets := uint64(0), uint64(0), 0
	for _, b := range f.cadence {
		if now.Unix()-b.second >= 0 && now.Unix()-b.second < 6 {
			replies += b.replies
			outgoing += b.outgoing
			if b.replies > 0 {
				buckets++
			}
		}
	}
	if outgoing < 6 {
		return
	}
	sustained := f.e.LastOutgoing.Sub(f.e.Started) >= ConfirmationSpan && replies >= 6 && buckets >= 3 && f.e.LastReply.Sub(f.e.FirstReply) >= ConfirmationSpan && now.Sub(f.e.LastReply) < 2*time.Second
	f.e.Sequence++
	if f.e.Stage == Local && (f.e.Fakes < uint64(f.e.Variant.Repeats*f.e.Variant.Cutoff) || f.e.FakeErrors > 0 || f.e.RateLimited > 0) {
		f.e.State = "LOCAL_PRIMING_INCOMPLETE"
		return
	}
	if f.primer {
		if sustained {
			f.e.State = "SUSTAINED_REPLIES"
			f.e.Reason = "TRANSPORT_CADENCE_CONFIRMED_NOT_MATCH_LOAD_PROOF"
		} else if now.Sub(f.e.Started) >= Probation {
			f.e.State = "INSUFFICIENT_REPLIES"
			f.e.Reason = "EXPLICIT_PRIMER_NO_AUTOMATIC_ADVANCE_OR_RELAY"
		}
		return
	}
	key := e.trialKey(f.key)
	old := e.learning[key]
	if old.LocalOnly != e.localOnly {
		old = Learning{}
	}
	if e.ladder && e.startLocal && old.Stage == Direct {
		old = Learning{}
	}
	if sustained && !f.learned {
		f.learned = true
		f.e.State = "SUSTAINED_REPLIES"
		f.e.Reason = "TRANSPORT_CADENCE_CONFIRMED_NOT_MATCH_LOAD_PROOF"
		index := 0
		for i, v := range Variants() {
			if v.ID == f.e.Variant.ID {
				index = i
			}
		}
		endpoint := ""
		if e.localOnly {
			endpoint = f.key.Destination.String()
		}
		if e.ladder && f.e.Stage == Direct {
			endpoint = f.key.Destination.String()
			key = endpointKey(f.key.Network, f.key.Application, endpoint)
		}
		e.putLearning(key, Learning{Endpoint: endpoint, Stage: f.e.Stage, Network: f.key.Network, Application: f.key.Application, Index: index, Confirmed: true, Expires: now.Add(LearnTTL)}, now)
		return
	}
	if f.learned {
		if sustained {
			f.degradedAt = time.Time{}
			f.e.State = "SUSTAINED_REPLIES"
			f.e.Reason = "TRANSPORT_CADENCE_CONFIRMED_NOT_MATCH_LOAD_PROOF"
		} else {
			if f.degradedAt.IsZero() {
				f.degradedAt = now
			}
			f.e.State = "CADENCE_PROBATION"
			f.e.Reason = "SPARSE_REPLIES_WHILE_OUTBOUND_CONTINUES"
		}
	}
	failed := !f.learned && now.Sub(f.e.Started) >= Probation || f.learned && (!f.degradedAt.IsZero() && now.Sub(f.degradedAt) >= Liveness || now.Sub(f.e.LastReply) >= Liveness)
	if !failed {
		return
	}
	f.failed = true
	f.e.State = "INSUFFICIENT_REPLIES"
	f.e.Reason = "NEXT_FLOW_ONLY_NO_REPLAY_OR_MIGRATION"
	index := 0
	for i, v := range Variants() {
		if v.ID == f.e.Variant.ID {
			index = i
		}
	}
	// A successful unrelated endpoint must neither hold a broken endpoint
	// DIRECT nor force its own healthy game traffic through relay.
	if e.ladder && f.e.Stage == Direct {
		delete(e.learning, endpointKey(f.key.Network, f.key.Application, f.key.Destination.String()))
		e.revision++
	}
	// Parallel failures of the same candidate advance only once. A losing trial
	// cannot overwrite a different sustained winner or drain all alternatives.
	if now.Before(old.Expires) && (old.Index != index || e.ladder && old.Stage != f.e.Stage) {
		return
	}
	if old.Confirmed {
		for _, peer := range e.flows {
			if peer != f && peer.key.Destination == f.key.Destination && peer.learned && !peer.failed && peer.degradedAt.IsZero() && e.trialKey(peer.key) == key && now.Sub(peer.e.LastReply) < 2*time.Second && now.Sub(peer.e.LastOutgoing) < 2*time.Second {
				f.e.Reason = "FLOW_FAILED_NETWORK_WINNER_STILL_RESPONDING"
				return
			}
		}
	}
	tried := old.Tried + 1
	if !now.Before(old.Expires) {
		tried = 1
	}
	next, stage, exhausted := index+1, f.e.Stage, false
	if e.ladder {
		switch f.e.Stage {
		case Direct:
			stage, next = Local, 0
		case Local:
			if next >= len(Variants()) {
				if e.localOnly {
					exhausted, next = true, index
					f.e.Reason = "GAME_UDP_LOCAL_ONLY_EXHAUSTED"
				} else {
					stage, next = Relay, 0
				}
			}
		case Relay:
			exhausted, next = true, 0
		}
	} else if next >= len(Variants()) {
		next = index
		tried = len(Variants())
		exhausted = true
	}
	expiry := now.Add(10 * time.Minute)
	if exhausted {
		expiry = now.Add(time.Hour)
	}
	endpoint := ""
	if e.localOnly {
		endpoint = f.key.Destination.String()
	}
	e.putLearning(key, Learning{Endpoint: endpoint, Stage: stage, Exhausted: exhausted, Network: f.key.Network, Application: f.key.Application, Index: next, Tried: tried, Expires: expiry}, now)
}
func (e *Engine) putLearning(key string, v Learning, now time.Time) {
	v.LocalOnly = e.localOnly
	if _, ok := e.learning[key]; !ok && len(e.learning) >= MaxNetworks {
		oldest := ""
		var at time.Time
		endpointVictim := false
		for k, entry := range e.learning {
			endpoint := entry.Endpoint != "" && entry.Stage == Direct && entry.Confirmed
			if oldest == "" || (endpoint && !endpointVictim) || (endpoint == endpointVictim && entry.Expires.Before(at)) {
				oldest, at, endpointVictim = k, entry.Expires, endpoint
			}
		}
		// Healthy QoS endpoints must not evict the bounded per-network failure
		// ladder. Evict a healthy endpoint first; no unbounded cache growth.
		if v.Endpoint != "" && v.Stage == Direct && v.Confirmed && !endpointVictim {
			return
		}
		delete(e.learning, oldest)
	}
	e.learning[key] = v
	e.revision++
}
func (e *Engine) cleanup(now time.Time) {
	for id, f := range e.flows {
		if now.Sub(f.last) > 2*time.Minute {
			delete(e.flows, id)
			e.lost++
		}
	}
	for k, v := range e.learning {
		if !now.Before(v.Expires) {
			delete(e.learning, k)
			e.revision++
		}
	}
}
func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	initialPolicy := "LOCAL_FIRST_UNCONFIRMED_ENDPOINT"
	if e.ladder && !e.startLocal {
		initialPolicy = "DIRECT_FIRST"
	}
	if e.primer != nil {
		initialPolicy = "EXPLICIT_ENDPOINT_INITIAL_PRIMER"
	}
	out := Snapshot{Primer: copyPrimer(e.primer), LocalOnly: e.localOnly, InitialPolicy: initialPolicy, Enabled: e.enabled, Application: e.application, Generation: e.generation, Reason: e.reason, Flows: []Evidence{}, Learning: []Learning{}, Lost: e.lost}
	for _, f := range e.flows {
		out.Flows = append(out.Flows, f.e)
	}
	for _, l := range e.learning {
		out.Learning = append(out.Learning, l)
	}
	sort.Slice(out.Flows, func(i, j int) bool { return out.Flows[i].ID > out.Flows[j].ID })
	sort.Slice(out.Learning, func(i, j int) bool {
		return out.Learning[i].Network+out.Learning[i].Endpoint < out.Learning[j].Network+out.Learning[j].Endpoint
	})
	return out
}
func (e *Engine) Revision() uint64 { e.mu.Lock(); defer e.mu.Unlock(); return e.revision }
func (e *Engine) Restore(all []Learning, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(all) > MaxNetworks {
		return errors.New("GAME_UDP_LEARNING_CAPACITY")
	}
	for _, l := range all {
		if l.LocalOnly && l.Stage == Relay {
			return errors.New("GAME_UDP_LEARNING_INVALID")
		}
		if l.Endpoint != "" {
			dst, err := netip.ParseAddrPort(l.Endpoint)
			if err != nil || !Eligible(l.Application, l.Application, "udp", dst) || !(l.Stage == Direct && l.Confirmed || l.LocalOnly && l.Stage == Local) {
				return errors.New("GAME_UDP_LEARNING_INVALID")
			}
		}
		if len(l.Network) != 64 || len(l.Application) > 2048 || l.Index < 0 || l.Index >= len(Variants()) || l.Tried < 0 || l.Tried > len(Variants())+2 || (l.Stage != "" && l.Stage != Direct && l.Stage != Local && l.Stage != Relay) || l.Expires.After(now.Add(LearnTTL)) {
			return errors.New("GAME_UDP_LEARNING_INVALID")
		}
	}
	for _, l := range all {
		if now.Before(l.Expires) {
			key := learnKey(l.Network, l.Application)
			if l.Endpoint != "" {
				key = endpointKey(l.Network, l.Application, l.Endpoint)
			}
			e.learning[key] = l
		}
	}
	return nil
}

func (e *Engine) Evidence(f *Flow) Evidence {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil || f.engine != e {
		return Evidence{}
	}
	return f.e
}

func (e *Engine) Ready() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.enabled && e.reason == "" }

// Budget is shared by all game profiles on a PC. It bounds amplification even
// when multiple games start together. No sleeps, queues or delayed originals.
type Budget struct {
	mu             sync.Mutex
	at             time.Time
	packets, bytes int
}

func (b *Budget) take(p, n int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.at.IsZero() || now.Sub(b.at) >= time.Second {
		b.at = now
		b.packets = 0
		b.bytes = 0
	}
	if b.packets+p > MaxFakePerSecond || b.bytes+n > MaxFakeBytesPerSecond {
		return false
	}
	b.packets += p
	b.bytes += n
	return true
}

// PinUnverifiedDirect is called before the first send when capture cannot prove
// the tuple was born after activation. Never prime or change egress of an
// already-used UDP tuple. This observation must not teach a candidate failure.
func (e *Engine) PinUnverifiedDirect(f *Flow) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil || f.engine != e || f.e.Outgoing != 0 || f.e.Fakes != 0 {
		return
	}
	f.e.Sequence++
	f.e.Stage = Direct
	f.payload = nil
	f.e.Variant = Variant{}
	f.ordinal = MaxCutoff + 1
	f.failed = true
	f.e.Selection = "EXISTING_TUPLE_PINNED_DIRECT"
	f.e.State = "NEW_FLOW_UNVERIFIED"
	f.e.Reason = "EXISTING_UDP_PINNED_DIRECT_NO_FIRST_FLIGHT_PROOF"
}

// Transport failure is evidence, not a fabricated server-health observation.
// A peer session/new flow remains eligible; an established flow is never replayed.
func (e *Engine) TransportFailed(f *Flow, cause string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil || f.engine != e || f.e.Stage != Relay || f.e.State == "TRANSPORT_FAILED" {
		return
	}
	if cause != "GAME_RELAY_OPEN_FAILED" {
		cause = "GAME_RELAY_TRANSPORT_FAILED"
	}
	f.e.Sequence++
	f.failed = true
	f.e.State = "TRANSPORT_FAILED"
	f.e.Reason = cause
}

// A physical network change invalidates training/remaining first flight of old
// flows. It does not move their packets or reuse results on the new network.
func (e *Engine) SetNetwork(network string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(network) != 64 {
		network = ""
	}
	if e.network != network {
		e.network = network
		e.generation++
	}
}
