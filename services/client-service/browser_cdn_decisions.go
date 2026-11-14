package clientservice

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/ipc"
)

const cdnDecisionLimit = 48

type cdnDecisionEvent struct {
	Seq          uint64                `json:"seq"`
	ConnectionID uint64                `json:"connection_id"`
	At           time.Time             `json:"at"`
	Host         string                `json:"host"`
	Destination  string                `json:"destination"`
	Ingress      string                `json:"ingress,omitempty"`
	HintOnly     bool                  `json:"hint_only,omitempty"`
	Stage        string                `json:"stage"`
	Phase        string                `json:"phase"`
	Reason       string                `json:"reason,omitempty"`
	Admission    string                `json:"local_admission,omitempty"`
	Strategy     string                `json:"strategy,omitempty"`
	TrialID      uint64                `json:"trial_id,omitempty"`
	RecordID     uint64                `json:"upstream_record_id,omitempty"`
	Selection    *cdnSelectionEvidence `json:"selection,omitempty"`
}

type cdnSelectionEvidence struct {
	CheckedAt time.Time                  `json:"checked_at"`
	Scope     youtubeKey                 `json:"scope"`
	Cache     *cdnCacheEvidence          `json:"cache"`
	Endpoint  *cdnEndpointCheck          `json:"endpoint_check,omitempty"`
	Peer      *cdnPeerEvidence           `json:"peer_proof,omitempty"`
	Trial     *cdnTrialAdmissionEvidence `json:"trial,omitempty"`
}

type cdnCacheEvidence struct {
	Stage     string    `json:"stage"`
	Confirmed bool      `json:"confirmed"`
	Strategy  string    `json:"strategy"`
	Until     time.Time `json:"until"`
	Qualified string    `json:"qualified,omitempty"`
}

func cdnCacheSnapshot(v youtubeLearn, found bool) *cdnCacheEvidence {
	if !found {
		return nil
	}
	return &cdnCacheEvidence{Stage: v.Stage, Confirmed: v.Confirmed, Strategy: v.Strategy, Until: v.Until, Qualified: v.Qualified}
}

type cdnEndpointCheck struct {
	Strategy string    `json:"strategy"`
	Blocked  bool      `json:"blocked"`
	Until    time.Time `json:"until,omitzero"`
}

type cdnPeerEvidence struct {
	Strategy    string    `json:"strategy"`
	Until       time.Time `json:"until"`
	DeniedUntil time.Time `json:"denied_until,omitzero"`
}

type cdnTrialAdmissionEvidence struct {
	CheckedAt time.Time         `json:"checked_at"`
	Cache     *cdnCacheEvidence `json:"cache"`
	Endpoint  *cdnEndpointCheck `json:"endpoint_check,omitempty"`
	Alternate *cdnEndpointCheck `json:"alternate_endpoint_check,omitempty"`
}

type cdnDecisionSnapshot struct {
	Schema     int                `json:"schema"`
	Build      string             `json:"build"`
	ServicePID int                `json:"service_pid"`
	LatestSeq  uint64             `json:"latest_seq"`
	Omitted    uint64             `json:"omitted"`
	Events     []cdnDecisionEvent `json:"events"`
}

// Caller holds mu. The initial event's sequence identifies all attempts for
// this connection. Later events have their own sequence for incremental reads.
func (r *youtubeRuntime) addCDNDecisionLocked(event cdnDecisionEvent) uint64 {
	r.cdnDecisionSeq++
	event.Seq = r.cdnDecisionSeq
	if event.ConnectionID == 0 {
		event.ConnectionID = event.Seq
	}
	event.At = time.Now().UTC()
	r.cdnDecisions[(event.Seq-1)%cdnDecisionLimit] = event
	return event.ConnectionID
}

func (r *youtubeRuntime) startCDNDecision(q browserproxy.Request, event cdnDecisionEvent) cdnDecisionEvent {
	host := strings.ToLower(strings.TrimSuffix(q.Host, "."))
	if !(host == "googlevideo.com" || strings.HasSuffix(host, ".googlevideo.com")) {
		return cdnDecisionEvent{}
	}
	return r.startOriginDecision(q, event)
}

func (r *youtubeRuntime) startOriginDecision(q browserproxy.Request, event cdnDecisionEvent) cdnDecisionEvent {
	host := strings.ToLower(strings.TrimSuffix(q.Host, "."))
	if !browserproxy.ValidPublicDNSName(host) {
		return cdnDecisionEvent{}
	}
	event.Host, event.Ingress, event.HintOnly = host, q.Ingress, q.HintOnly
	if event.Phase == "" {
		event.Phase = "SELECTED"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	event.ConnectionID = r.addCDNDecisionLocked(event)
	return event
}

func (r *youtubeRuntime) cdnDecisionSnapshot() cdnDecisionSnapshot {
	build := buildStamp()
	r.mu.Lock()
	latest := r.cdnDecisionSeq
	count := min(latest, cdnDecisionLimit)
	omitted := latest - count
	events := make([]cdnDecisionEvent, 0, count)
	for seq := omitted; seq < latest; seq++ {
		events = append(events, r.cdnDecisions[seq%cdnDecisionLimit])
	}
	r.mu.Unlock()

	// Evidence is immutable after publication. Keep the newest complete events
	// and reserve space for the IPC envelope and snapshot metadata.
	size := 0
	for i := len(events) - 1; i >= 0; i-- {
		data, err := json.Marshal(events[i])
		size += len(data) + 1
		if err != nil || size > ipc.MaxMessage-4096 {
			events = events[i+1:]
			omitted += uint64(i + 1)
			break
		}
	}
	return cdnDecisionSnapshot{Schema: 1, Build: build, ServicePID: os.Getpid(), LatestSeq: latest, Omitted: omitted, Events: events}
}
