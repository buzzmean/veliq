package clubhealth

import "regexp"

// Unknown is the zero value for a signal. A missing or stale measurement must
// not be encoded as Failed/Available by the producer.
type Signal uint8

const (
	Unknown Signal = iota
	Available
	Failed
)

type IncidentKind string

const (
	IncidentHeartbeatGap   IncidentKind = "heartbeat_gap"
	IncidentLanGame        IncidentKind = "langame"
	IncidentInternet       IncidentKind = "internet"
	IncidentShutdown       IncidentKind = "shutdown"
	IncidentCapture        IncidentKind = "capture"
	IncidentVELIQCrash     IncidentKind = "veliq_crash"
	IncidentVELIQStart     IncidentKind = "veliq_start"
	IncidentVELIQCP        IncidentKind = "veliq_cp"
	IncidentVELIQRelay     IncidentKind = "veliq_relay"
	IncidentProtectedRoute IncidentKind = "protected_route"
)

type ProtectedKind string

const (
	ProtectedLanGame ProtectedKind = "langame"
	ProtectedISCSI   ProtectedKind = "iscsi"
)

type RelayStage string

const (
	RelayBlocked   RelayStage = "blocked_before_open"
	RelayAttempted RelayStage = "open_attempted"
	RelayOpened    RelayStage = "authenticated_open"
	RelayRelayed   RelayStage = "bytes_relayed"
)

// ProtectedRelayEvidence identifies a local routing decision for a verified
// protected flow. IDs are pseudonymous and scoped to a device and service
// epoch. Sequence is ordered by the instrumentation for this open, not an
// unrelated server clock. An unknown ID never joins another unknown ID.
type ProtectedRelayEvidence struct {
	Protected ProtectedKind `json:"protected"`
	DeviceID  string        `json:"device_id,omitzero"`
	Epoch     string        `json:"epoch,omitzero"`
	FlowID    string        `json:"flow_id,omitzero"`
	OpenID    string        `json:"open_id,omitzero"`
	Sequence  uint64        `json:"sequence,omitzero"`
	Stage     RelayStage    `json:"stage"`
}

// RelayFact is a trusted producer's record of the specific relay open. Only
// the relay adapter should set Authenticated based on the existing authenticated
// protocol, not on the client having reached TCP/QUIC or received any response.
type RelayFact struct {
	DeviceID      string `json:"device_id,omitzero"`
	Epoch         string `json:"epoch,omitzero"`
	FlowID        string `json:"flow_id,omitzero"`
	OpenID        string `json:"open_id,omitzero"`
	Sequence      uint64 `json:"sequence,omitzero"`
	Authenticated bool   `json:"authenticated,omitzero"`
	Bytes         uint64 `json:"bytes,omitzero"`
}

// IDs may be keyed hashes or random tokens, never paths, endpoints, or names.
var evidenceID = regexp.MustCompile("^[0-9a-f]{16,64}$")

func (v ProtectedRelayEvidence) Valid() bool {
	return (v.Protected == ProtectedLanGame || v.Protected == ProtectedISCSI) &&
		evidenceID.MatchString(v.DeviceID) && evidenceID.MatchString(v.Epoch) &&
		evidenceID.MatchString(v.FlowID) && v.Sequence != 0 &&
		(v.Stage == RelayBlocked && (v.OpenID == "" || evidenceID.MatchString(v.OpenID)) ||
			v.Stage == RelayAttempted && evidenceID.MatchString(v.OpenID))
}

func MatchProtectedRelayEvidence(decision ProtectedRelayEvidence, fact RelayFact) RelayStage {
	if !decision.Valid() {
		return ""
	}
	if decision.Stage == RelayBlocked {
		return RelayBlocked
	}
	if decision.Stage != RelayAttempted || decision.OpenID == "" {
		return ""
	}
	if !fact.Authenticated || fact.DeviceID != decision.DeviceID || fact.Epoch != decision.Epoch ||
		fact.FlowID != decision.FlowID || fact.OpenID != decision.OpenID || fact.Sequence <= decision.Sequence {
		return RelayAttempted
	}
	if fact.Bytes != 0 {
		return RelayRelayed
	}
	return RelayOpened
}

type IncidentObservation struct {
	Kind                  IncidentKind `json:"kind"`
	WindowsLive           Signal       `json:"windows_live,omitzero"`
	DirectInternet        Signal       `json:"direct_internet,omitzero"`
	ObserverReachability  Signal       `json:"observer_reachability,omitzero"`
	ComponentReachability Signal       `json:"component_reachability,omitzero"`
	// Confirmed identifies positive product evidence (e.g. service owner and
	// termination, not an arbitrary process basename or elapsed timeout).
	Confirmed             bool                   `json:"confirmed,omitzero"`
	Sustained             bool                   `json:"sustained,omitzero"`
	OptimizationRequested bool                   `json:"optimization_requested,omitzero"`
	Planned               bool                   `json:"planned,omitzero"`
	RecoveredWithFallback bool                   `json:"recovered_with_fallback,omitzero"`
	ProtectedDecision     ProtectedRelayEvidence `json:"protected_decision,omitzero"`
	RelayFact             RelayFact              `json:"relay_fact,omitzero"`
}

func (v IncidentObservation) Valid() bool {
	if v.WindowsLive > Failed || v.DirectInternet > Failed || v.ObserverReachability > Failed || v.ComponentReachability > Failed {
		return false
	}
	switch v.Kind {
	case IncidentProtectedRoute:
		return v.ProtectedDecision.Valid()
	case IncidentHeartbeatGap, IncidentLanGame, IncidentInternet, IncidentShutdown, IncidentCapture,
		IncidentVELIQCrash, IncidentVELIQStart, IncidentVELIQCP, IncidentVELIQRelay:
		return v.ProtectedDecision == (ProtectedRelayEvidence{}) && v.RelayFact == (RelayFact{})
	}
	return false
}

// ValidClient rejects evidence assertions that must be filled by independent
// server/relay adapters. The authenticated report's device binding is checked
// separately by ingestion rather than inferred from the claimed evidence ID.
func (v IncidentObservation) ValidClient() bool {
	return v.Valid() && v.ObserverReachability == Unknown && v.RelayFact == (RelayFact{})
}

type IncidentDecision struct {
	Alert bool         `json:"alert"`
	Class IncidentKind `json:"class"`
	// Scope is component-wide only when an independent observer positively
	// confirms that the same component is unavailable.
	Scope      string     `json:"scope,omitzero"`
	RouteStage RelayStage `json:"route_stage,omitzero"`
	// Subsequent shutdown cause is always outside this classifier's evidence.
	// Correlate its chronology in a separate report, not by inferring cause.
}

func ClassifyIncident(v IncidentObservation) IncidentDecision {
	d := IncidentDecision{Class: v.Kind}
	if !v.Valid() {
		return d
	}
	if v.Kind == IncidentProtectedRoute {
		d.RouteStage = MatchProtectedRelayEvidence(v.ProtectedDecision, v.RelayFact)
		// A protected profile blocked before open is the guard working.
		// Even an authenticated open with zero data is not relayed traffic.
		d.Alert = d.RouteStage == RelayRelayed
		return d
	}
	if v.Planned || v.RecoveredWithFallback || !v.Confirmed ||
		v.WindowsLive != Available || v.DirectInternet != Available {
		return d
	}
	switch v.Kind {
	case IncidentCapture:
		d.Alert = v.OptimizationRequested && v.Sustained
	case IncidentVELIQCrash:
		d.Alert = true
	case IncidentVELIQStart:
		d.Alert = v.Sustained
	case IncidentVELIQCP, IncidentVELIQRelay:
		if !v.Sustained || v.ComponentReachability != Failed {
			break
		}
		switch v.ObserverReachability {
		case Available:
			d.Alert, d.Scope = true, "network_path"
		case Failed:
			d.Alert, d.Scope = true, "component"
		}
	}
	return d
}
