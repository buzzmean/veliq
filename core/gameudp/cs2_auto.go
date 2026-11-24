package gameudp

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

// CS2Outcome is evidence from the game for one captured connection. UDP
// directions, cadence and a successful relay OPEN do not prove admission.
type CS2Outcome struct {
	Phase       string         `json:"phase,omitempty"`
	FlowID      uint64         `json:"flow_id"`
	Started     time.Time      `json:"started_at"`
	PID         uint32         `json:"pid"`
	Birth       uint64         `json:"creation_time"`
	Destination netip.AddrPort `json:"destination"`
	Outcome     string         `json:"outcome"`
	Quality     *CS2Quality    `json:"quality,omitempty"`
}

type CS2Quality struct {
	RTTMS         float64 `json:"rtt_ms"`
	JitterMS      float64 `json:"jitter_ms"`
	LossPct       float64 `json:"loss_pct"`
	Samples       int     `json:"samples"`
	StableSeconds int     `json:"stable_seconds"`
}

const (
	LocalSocket     = "LOCAL_SOCKET"
	cs2TrialTTL     = 10 * time.Minute
	cs2EvidenceTTL  = 30 * time.Minute
	cs2MaxEndpoints = 32
)

// All fields are required on the wire. Zero jitter and loss are legitimate
// measurements only when explicitly supplied.
func (q *CS2Quality) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if len(fields) != 5 {
		return errors.New("CS2_QUALITY_FIELDS_REQUIRED")
	}
	for _, name := range []string{"rtt_ms", "jitter_ms", "loss_pct", "samples", "stable_seconds"} {
		value, ok := fields[name]
		if !ok || string(value) == "null" {
			return errors.New("CS2_QUALITY_FIELDS_REQUIRED")
		}
	}
	type plain CS2Quality
	return json.Unmarshal(raw, (*plain)(q))
}

func (q CS2Quality) valid() bool {
	return q.Samples >= 20 && q.Samples <= 1000000 && q.StableSeconds >= 30 &&
		q.StableSeconds <= 86400 && q.RTTMS > 0 && q.RTTMS <= 60000 &&
		q.JitterMS >= 0 && q.JitterMS <= 60000 && q.LossPct >= 0 && q.LossPct <= 100
}

// CS2Endpoint retains the latest observed join for this game, network and
// server when the short-lived captured UDP flow has already aged out.
type CS2Endpoint struct {
	restored    bool
	Stage       string `json:"stage"`
	lastSource  netip.AddrPort
	lastPID     uint32
	lastBirth   uint64
	lateReply   bool
	trialAt     time.Time
	trialFlow   uint64
	Network     string         `json:"network_fingerprint"`
	Destination netip.AddrPort `json:"destination"`
	FlowID      uint64         `json:"flow_id"`
	ObservedAt  time.Time      `json:"observed_at"`
	Outcome     string         `json:"outcome"`
	Phase       string         `json:"phase,omitempty"`
	Quality     *CS2Quality    `json:"quality,omitempty"`
}

func (e *Engine) SetCS2Auto(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cs2Auto != enabled {
		e.cs2Auto = enabled
		e.cs2Endpoints = nil
		e.generation++
	}
}

func (e *Engine) OpenCS2(k Key, now time.Time) (*Flow, error) {
	return e.open(k, now, "", true)
}

// A local socket still reaches the real peer directly over the Windows route.
// It may be tried once on a fresh tuple, following a verified pre-admission
// failure. No copy of an earlier datagram is replayed on the other path.
func (e *Engine) cs2Route(k Key, now time.Time) (string, string) {
	key := endpointKey(k.Network, k.Application, k.Destination.String())
	row := e.cs2Endpoints[key]
	var active *Flow
	for _, f := range e.flows {
		if f.cs2Auto && f.generation == e.generation && f.key.PID == k.PID && f.key.Birth == k.Birth &&
			f.key.Destination == k.Destination && f.key.Network == k.Network && f.e.JoinOutcome == "JOINED" &&
			!f.failed && now.Sub(f.e.LastOutgoing) < Liveness && now.Sub(f.e.LastReply) < Liveness {
			if active == nil || f.e.ID > active.e.ID {
				active = f
			}
		}
	}
	if active != nil {
		return active.e.Stage, "CS2_ACTIVE_MATCH_PINNED"
	}
	if row.Outcome == "JOINED" && now.Before(row.ObservedAt.Add(cs2EvidenceTTL)) {
		if row.Stage == Local && e.stunAuto {
			return Local, "CS2_STUN687_CONFIRMED"
		}
		if row.Stage == LocalSocket {
			return LocalSocket, "CS2_LOCAL_SOCKET_CONFIRMED"
		}
		return Direct, "CS2_DIRECT_CONFIRMED"
	}
	earlyFailure := row.Outcome == "TIMEOUT" && row.Phase == "NO_REPLY_OBSERVED" && !row.lateReply || row.Outcome == "LOCAL_SEND_FAILED"
	freshSocket := row.lastSource != k.Source || row.lastPID != k.PID || row.lastBirth != k.Birth
	if row.Stage == Direct && earlyFailure && freshSocket && !now.Before(row.ObservedAt) && now.Before(row.ObservedAt.Add(cs2TrialTTL)) &&
		(row.trialAt.IsZero() || !now.Before(row.trialAt.Add(cs2TrialTTL))) {
		row.trialAt, row.trialFlow = now, e.next+1
		e.cs2Endpoints[key] = row
		if e.stunAuto {
			return Local, "CS2_STUN687_TRIAL"
		}
		return LocalSocket, "CS2_LOCAL_SOCKET_TRIAL"
	}
	return Direct, "CS2_DIRECT_DEFAULT"
}

// Caller observed a definite local transport error before the OS accepted
// the first original payload. An uncertain send or mid-game error cannot
// authorize switching a tuple.
func (e *Engine) CS2LocalFailure(f *Flow, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.cs2Auto || f == nil || !f.cs2Auto || f.engine != e || e.flows[f.e.ID] != f ||
		f.generation != e.generation || f.failed || f.e.Outgoing != 0 || f.e.Replies != 0 || f.e.JoinOutcome != "" {
		return
	}
	f.failed = true
	f.e.State, f.e.Reason, f.e.JoinOutcome = "TRANSPORT_FAILED", "CS2_FIRST_LOCAL_SEND_FAILED", "LOCAL_SEND_FAILED"
	f.e.Sequence++
	e.rememberCS2(f, now)
}

func (e *Engine) RecordCS2Outcome(o CS2Outcome, now time.Time) error {
	return e.recordCS2(o, now, false)
}

// Supplement a game-confirmed join using measurements tied to the same flow.
// A manual quality sample cannot assert that a connection succeeded or failed.
func (e *Engine) RecordCS2Quality(o CS2Outcome, now time.Time) error {
	return e.recordCS2(o, now, true)
}

func (e *Engine) recordCS2(o CS2Outcome, now time.Time, supplementOnly bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	f := e.flows[o.FlowID]
	if !e.cs2Auto || !e.enabled || e.reason != "" || f == nil || !f.cs2Auto || f.generation != e.generation ||
		f.e.Selection == "EXISTING_TUPLE_PINNED_DIRECT" || f.failed || !o.Started.Equal(f.e.Started) ||
		o.PID != f.key.PID || o.Birth != f.key.Birth || o.Destination != f.key.Destination || f.e.Outgoing == 0 ||
		now.Before(f.e.Started) || f.last.Sub(now) > time.Second || now.Sub(f.last) > 90*time.Second {
		return errors.New("CS2_OUTCOME_FLOW_MISMATCH")
	}
	switch o.Phase {
	case "", "NO_REPLY_OBSERVED", "TRANSPORT_ONLY", "SERVER_ACCEPTED", "SIGNONSTATE_NONE", "SIGNONSTATE_CHALLENGE", "SIGNONSTATE_CONNECTED", "SIGNONSTATE_NEW", "SIGNONSTATE_PRESPAWN", "SIGNONSTATE_SPAWN", "SIGNONSTATE_FULL", "SIGNONSTATE_CHANGELEVEL", "INGAME":
	default:
		return errors.New("CS2_PHASE_INVALID")
	}
	if (o.Phase == "NO_REPLY_OBSERVED" && f.e.Replies > 0) || (o.Phase == "INGAME" && o.Outcome != "JOINED") ||
		(supplementOnly && o.Phase != "") || (f.e.JoinPhase != "" && o.Phase != "" && f.e.JoinPhase != o.Phase) {
		return errors.New("CS2_PHASE_CONFLICT")
	}
	switch o.Outcome {
	case "JOINED":
		if f.e.Replies == 0 {
			return errors.New("CS2_JOIN_REPLIES_MISSING")
		}
	case "TIMEOUT":
		if now.Sub(f.e.Started) < time.Second {
			return errors.New("CS2_TIMEOUT_INTERVAL_TOO_SHORT")
		}
	case "DENIED", "FULL", "UNKNOWN":
	default:
		return errors.New("CS2_OUTCOME_INVALID")
	}
	if supplementOnly && (f.e.JoinOutcome != "JOINED" || o.Outcome != "JOINED" || o.Quality == nil) {
		return errors.New("CS2_CONFIRMED_JOIN_REQUIRED")
	}
	if f.e.JoinOutcome != "" && f.e.JoinOutcome != o.Outcome {
		return errors.New("CS2_OUTCOME_CONFLICT")
	}
	if o.Quality != nil {
		q := *o.Quality
		if o.Outcome != "JOINED" || !q.valid() || q.StableSeconds > int(f.e.LastReply.Sub(f.e.Started)/time.Second) {
			return errors.New("CS2_QUALITY_INVALID")
		}
		if f.e.GameQuality != nil && *f.e.GameQuality != q {
			return errors.New("CS2_QUALITY_ALREADY_RECORDED")
		}
	}
	if f.e.JoinOutcome == o.Outcome && (o.Quality == nil || f.e.GameQuality != nil) {
		return nil
	}
	if o.Quality != nil {
		q := *o.Quality
		f.e.GameQuality = &q
	}
	if o.Phase != "" {
		f.e.JoinPhase = o.Phase
	}
	f.e.JoinOutcome = o.Outcome
	f.e.Sequence++
	f.e.State = o.Outcome
	f.e.Reason = "CS2_GAME_OUTCOME"
	e.rememberCS2(f, now)
	return nil
}

func (e *Engine) rememberCS2(f *Flow, now time.Time) {
	if e.cs2Endpoints == nil {
		e.cs2Endpoints = make(map[string]CS2Endpoint)
	}
	key := endpointKey(f.key.Network, f.key.Application, f.key.Destination.String())
	record, exists := e.cs2Endpoints[key]
	if exists && f.e.ID < record.FlowID {
		return
	}
	if !exists && len(e.cs2Endpoints) >= cs2MaxEndpoints {
		var oldest string
		var at time.Time
		for k, row := range e.cs2Endpoints {
			if oldest == "" || row.ObservedAt.Before(at) {
				oldest, at = k, row.ObservedAt
			}
		}
		delete(e.cs2Endpoints, oldest)
	}
	e.cs2Endpoints[key] = CS2Endpoint{Network: f.key.Network, Destination: f.key.Destination, FlowID: f.e.ID,
		Stage: f.e.Stage, lastSource: f.key.Source, lastPID: f.key.PID, lastBirth: f.key.Birth,
		trialAt: record.trialAt, trialFlow: record.trialFlow,
		ObservedAt: now, Outcome: f.e.JoinOutcome, Phase: f.e.JoinPhase, Quality: f.e.GameQuality}
}

func copyCS2Quality(q *CS2Quality) *CS2Quality {
	if q == nil {
		return nil
	}
	v := *q
	return &v
}

func (f *Flow) evidence() Evidence {
	v := f.e
	v.GameQuality = copyCS2Quality(v.GameQuality)
	return v
}
