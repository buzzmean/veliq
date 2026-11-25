package clubhealth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/buzzmean/veliq/core/security"
)

const PersistentEndpoint = Endpoint + "/persistent"
const JournalBytes = 4 << 20
const JournalEvents = 4096
const InputEvents = 256
const ServerDeviceEvents = 8192

var label = regexp.MustCompile(`^[\p{L}\p{N}_.()+ -]{1,80}$`)
var symbol = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)

// Diagnostic is a metadata allowlist, never an error message, URL, certificate,
// account name, command line or packet. Attribution is deliberately not inferred.
type Diagnostic struct {
	ID              string    `json:"id"`
	At              time.Time `json:"at"`
	PC              string    `json:"pc"`
	Version         string    `json:"version"`
	Source          string    `json:"source"`
	Session         string    `json:"session"`
	ServicePID      uint32    `json:"service_pid"`
	Observer        string    `json:"observer"`
	Component       string    `json:"component"`
	State           string    `json:"state"`
	Incident        string    `json:"incident,omitempty"`
	Code            string    `json:"code"`
	NativeCode      uint32    `json:"native_code,omitempty"`
	ProviderState   uint32    `json:"provider_state,omitempty"`
	Operation       string    `json:"operation,omitempty"`
	EventID         uint32    `json:"event_id,omitempty"`
	RecordID        uint64    `json:"record_id,omitempty"`
	PID             uint32    `json:"pid,omitempty"`
	Birth           uint64    `json:"birth,omitempty"`
	App             string    `json:"app,omitempty"`
	ProcessVerified bool      `json:"process_verified,omitempty"`
	Port            uint16    `json:"port,omitempty"`
	Lost            uint64    `json:"lost,omitempty"`
}

func (e Diagnostic) Valid(now time.Time) bool {
	if !eventID.MatchString(e.ID) || !eventID.MatchString(e.Session) ||
		!label.MatchString(e.PC) || !buildID.MatchString(e.Version) || !buildID.MatchString(e.Source) ||
		!symbol.MatchString(e.Observer) || !symbol.MatchString(e.Component) || !symbol.MatchString(e.Code) ||
		e.Operation != "" && !symbol.MatchString(e.Operation) ||
		e.Incident != "" && !eventID.MatchString(e.Incident) ||
		e.App != "" && !ValidApp(e.App) || e.ProcessVerified && (e.PID == 0 || e.Birth == 0 || e.App == "") ||
		e.At.Before(now.Add(-Retention)) || e.At.After(now.Add(time.Minute)) {
		return false
	}
	switch e.State {
	case "failed", "recovered", "observed", "unknown", "ready":
		return true
	}
	return false
}

type Batch struct {
	Protocol int          `json:"protocol"`
	Events   []Diagnostic `json:"events"`
}
type PersistentRequest struct {
	Batch Batch          `json:"batch"`
	Proof security.Proof `json:"proof"`
}

// Digest acknowledges exactly the committed batch, including empty heartbeats.
// HTTP success alone never removes pending events.
type Receipt struct {
	Protocol  int    `json:"protocol"`
	Digest    string `json:"digest"`
	Committed bool   `json:"committed"`
}

func (b Batch) Audience() string {
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	return "club-health-persistent-v1:" + hex.EncodeToString(sum[:])
}
func (b Batch) Validate(now time.Time) error {
	if b.Protocol != 1 || len(b.Events) > MaxEvents {
		return errors.New("invalid diagnostic batch")
	}
	seen := map[string]bool{}
	for _, e := range b.Events {
		if !e.Valid(now) || seen[e.ID] {
			return errors.New("invalid diagnostic event")
		}
		seen[e.ID] = true
	}
	return nil
}
func (r Receipt) Accepts(b Batch) bool {
	return r.Protocol == 1 && r.Committed && r.Digest == b.Audience()
}

// Transition records recovery only after positive evidence for the same key.
// Silence, stale samples, process exit and unavailable observers are not recovery.
type Transitions struct {
	Active   map[string]string `json:"active,omitempty"`
	Previous map[string]string `json:"previous,omitempty"`
}

func (t *Transitions) Observe(key string, e Diagnostic) (Diagnostic, bool) {
	if t.Active == nil {
		t.Active = map[string]string{}
	}
	if t.Previous == nil {
		t.Previous = map[string]string{}
	}
	fingerprint := fmt.Sprintf("%s:%s:%08x:%08x:%s:%d:%d", e.State, e.Code, e.NativeCode, e.ProviderState, e.Operation, e.PID, e.Birth)
	if t.Previous[key] == fingerprint {
		return e, false
	}
	t.Previous[key] = fingerprint
	if e.State == "failed" {
		if t.Active[key] == "" {
			t.Active[key] = e.ID
		}
		e.Incident = t.Active[key]
	} else if e.State == "ready" && t.Active[key] != "" {
		e.State, e.Incident = "recovered", t.Active[key]
		delete(t.Active, key)
	}
	return e, true
}
