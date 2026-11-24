package browserproxy

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
)

// FirstByteMetric measures encrypted transport progress, NOT HTTP/page success.
// One sample per CONNECT, including DNS/OPEN, admission and initial stall retry.
// NoReply is separate: failures never become zero-latency successes.
type FirstByteMetric struct {
	NoReplyReasons        map[string]uint64 `json:"no_reply_reasons"`
	NoReplyWithoutRequest uint64            `json:"no_reply_without_request_payload"`
	NoReplyWithRequest    uint64            `json:"no_reply_with_request_payload"`
	NoReplyOriginSeen     uint64            `json:"no_reply_origin_payload_seen"`
	Port                  uint16            `json:"port"`
	Network               string            `json:"network"`
	Profile               string            `json:"profile_id"`
	Group                 string            `json:"group"`
	Path                  string            `json:"path"`
	Mode                  string            `json:"mode"`
	Replies               uint64            `json:"replies"`
	NoReply               uint64            `json:"closed_without_reply"`
	TotalMS               float64           `json:"total_ms"`
	MinMS                 float64           `json:"min_ms"`
	MaxMS                 float64           `json:"max_ms"`
	LastMS                float64           `json:"last_ms"`
}
type firstByteKey struct {
	network, profile, group, path, mode string
	port                                uint16
}
type firstByteLedger struct {
	mu   sync.Mutex
	rows map[firstByteKey]FirstByteMetric
	lost uint64
}

func firstByteMode(p Plan) string {
	if p.DirectAttempts > 0 || p.Policy.Action == flowpolicy.Direct {
		return "DIRECT_FIRST"
	}
	switch p.Policy.Action {
	case flowpolicy.Relay, flowpolicy.RelayRequired:
		return "RELAY_FIRST"
	case flowpolicy.DirectPlus:
		return "DIRECT_PLUS"
	}
	return "UNROUTED"
}
func (l *firstByteLedger) observe(r Record, elapsed time.Duration) {
	group := flowpolicy.BrowserRelayGroup(r.Domain)
	if group == "" {
		group = r.Domain
	}
	key := firstByteKey{r.Plan.Network, r.Owner.Profile, group, r.EvidenceSource, r.FirstByteMode, r.Port}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rows == nil {
		l.rows = map[firstByteKey]FirstByteMetric{}
	}
	m, ok := l.rows[key]
	if !ok {
		if len(l.rows) >= 128 {
			l.lost++
			return
		}
		m = FirstByteMetric{Port: key.port, Network: key.network, Profile: key.profile, Group: key.group, Path: key.path, Mode: key.mode, MinMS: -1, MaxMS: -1, LastMS: -1}
	}
	if elapsed < 0 {
		m.NoReply++
		if m.NoReplyReasons == nil {
			m.NoReplyReasons = map[string]uint64{}
		}
		reason := r.NoReplyReason
		if reason == "" {
			reason = "UNCLASSIFIED"
		}
		m.NoReplyReasons[reason]++
		if r.RequestPayloadSeen {
			m.NoReplyWithRequest++
		} else {
			m.NoReplyWithoutRequest++
		}
		if r.OriginPayloadSeen {
			m.NoReplyOriginSeen++
		}
	} else {
		ms := float64(elapsed) / float64(time.Millisecond)
		if m.Replies == 0 || ms < m.MinMS {
			m.MinMS = ms
		}
		if ms > m.MaxMS {
			m.MaxMS = ms
		}
		m.Replies++
		m.TotalMS += ms
		m.LastMS = ms
	}
	l.rows[key] = m
}
func (l *firstByteLedger) snapshot() ([]FirstByteMetric, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]FirstByteMetric, 0, len(l.rows))
	for _, m := range l.rows {
		if m.NoReplyReasons != nil {
			copyReasons := make(map[string]uint64, len(m.NoReplyReasons))
			for reason, count := range m.NoReplyReasons {
				copyReasons[reason] = count
			}
			m.NoReplyReasons = copyReasons
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Network != b.Network {
			return a.Network < b.Network
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Mode < b.Mode
	})
	return out, l.lost
}

// A separate IPC report prevents optional timing summaries from evicting routing
// evidence in browser.status. Its own omissions are explicit and independently bounded.
type FirstByteReport struct {
	Scope     string            `json:"scope"`
	Metrics   []FirstByteMetric `json:"first_byte_metrics"`
	Lost      uint64            `json:"first_byte_metrics_lost"`
	Omitted   uint64            `json:"first_byte_rows_omitted"`
	Truncated bool              `json:"truncated"`
}

func (s *Server) FirstBytes() FirstByteReport {
	out := FirstByteReport{Scope: "PAC frontend TCP accept to first delivered upstream byte (may be TLS); not HTTP/page success", Metrics: []FirstByteMetric{}}
	if s != nil {
		out.Metrics, out.Lost = s.firstBytes.snapshot()
		out.Truncated = out.Lost != 0
	}
	for {
		raw, _ := json.Marshal(out)
		if len(raw) < 57000 || len(out.Metrics) == 0 {
			break
		}
		out.Metrics = out.Metrics[:len(out.Metrics)-1]
		out.Omitted++
		out.Truncated = true
	}
	return out
}
