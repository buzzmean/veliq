package clientservice

import (
	"os"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

const cdnDecisionLimit = 48

type cdnDecisionEvent struct {
	Seq          uint64    `json:"seq"`
	ConnectionID uint64    `json:"connection_id"`
	At           time.Time `json:"at"`
	Host         string    `json:"host"`
	Destination  string    `json:"destination"`
	Ingress      string    `json:"ingress,omitempty"`
	HintOnly     bool      `json:"hint_only,omitempty"`
	Stage        string    `json:"stage"`
	Phase        string    `json:"phase"`
	Reason       string    `json:"reason,omitempty"`
	Admission    string    `json:"local_admission,omitempty"`
	Strategy     string    `json:"strategy,omitempty"`
	TrialID      uint64    `json:"trial_id,omitempty"`
	RecordID     uint64    `json:"upstream_record_id,omitempty"`
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
	if !(host == "googlevideo.com" || strings.HasSuffix(host, ".googlevideo.com")) || !browserproxy.ValidPublicDNSName(host) {
		return cdnDecisionEvent{}
	}
	event.Host, event.Ingress, event.HintOnly, event.Phase = host, q.Ingress, q.HintOnly, "SELECTED"
	r.mu.Lock()
	defer r.mu.Unlock()
	event.ConnectionID = r.addCDNDecisionLocked(event)
	return event
}

func (r *youtubeRuntime) cdnDecisionSnapshot() cdnDecisionSnapshot {
	build := buildStamp()
	r.mu.Lock()
	defer r.mu.Unlock()
	count := min(r.cdnDecisionSeq, cdnDecisionLimit)
	omitted := r.cdnDecisionSeq - count
	events := make([]cdnDecisionEvent, 0, count)
	for seq := omitted; seq < r.cdnDecisionSeq; seq++ {
		events = append(events, r.cdnDecisions[seq%cdnDecisionLimit])
	}
	return cdnDecisionSnapshot{Schema: 1, Build: build, ServicePID: os.Getpid(), LatestSeq: r.cdnDecisionSeq, Omitted: omitted, Events: events}
}
