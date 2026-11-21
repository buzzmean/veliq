package browserproxy

import "time"

// PathMetrics are cumulative since this listener started, independent of the
// bounded record ledger. Bytes/OPEN never certify an HTTP result or page load.
type PathMetrics struct {
	Profile         string    `json:"profile_id"`
	Started         time.Time `json:"started_at"`
	FirstOpened     time.Time `json:"first_tunnel_opened_at,omitzero"`
	FirstExchange   time.Time `json:"first_bidirectional_exchange_at,omitzero"`
	FirstOpenMS     int64     `json:"listen_to_first_open_ms"`
	FirstExchangeMS int64     `json:"listen_to_first_exchange_ms"`
	Accepted        uint64    `json:"accepted"`
	Opened          uint64    `json:"opened"`
	Failed          uint64    `json:"failed"`
	Active          uint64    `json:"active"`
	Sent            uint64    `json:"sent_bytes"`
	Received        uint64    `json:"received_bytes"`
}
type FailureSummary struct {
	Profile      string    `json:"profile_id"`
	Domain       string    `json:"domain"`
	Phase        string    `json:"phase"`
	Reason       string    `json:"reason"`
	Route        string    `json:"route"`
	Destination  string    `json:"destination"`
	PolicySource string    `json:"policy_source"`
	Count        uint64    `json:"count"`
	Last         time.Time `json:"last_at"`
}

func (s *Server) pathFailureLocked(r Record, phase, reason string) {
	key := r.Owner.Profile + "\x00" + r.Domain + "\x00" + phase + "\x00" + reason + "\x00" + string(r.Plan.Policy.Action) + "\x00" + r.Plan.Destination.String() + "\x00" + r.Plan.Policy.Source
	if s.failureDetails == nil {
		s.failureDetails = map[string]FailureSummary{}
	}
	f, ok := s.failureDetails[key]
	if !ok && len(s.failureDetails) >= 128 {
		s.failureDetailsLost++
		return
	}
	f.Profile, f.Domain, f.Phase, f.Reason = r.Owner.Profile, r.Domain, phase, reason
	f.Route = string(r.Plan.Policy.Action)
	f.Destination = r.Plan.Destination.String()
	f.PolicySource = r.Plan.Policy.Source
	f.Count++
	f.Last = time.Now()
	s.failureDetails[key] = f
}
func (s *Server) pathBeginLocked(profile string) {
	if s.paths == nil {
		s.paths = map[string]PathMetrics{}
	}
	p, ok := s.paths[profile]
	if !ok {
		if len(s.paths) >= 128 {
			s.metricsLost++
			return
		}
		p = PathMetrics{Profile: profile, Started: s.started, FirstOpenMS: -1, FirstExchangeMS: -1}
	}
	p.Accepted++
	s.paths[profile] = p
}
func (s *Server) pathOpenedLocked(profile string) {
	p, ok := s.paths[profile]
	if !ok {
		return
	}
	p.Opened++
	p.Active++
	if p.FirstOpened.IsZero() {
		p.FirstOpened = time.Now()
		p.FirstOpenMS = p.FirstOpened.Sub(p.Started).Milliseconds()
	}
	s.paths[profile] = p
}
func (s *Server) pathBytesLocked(r Record, tx, rx uint64) {
	p, ok := s.paths[r.Owner.Profile]
	if !ok {
		return
	}
	p.Sent += tx
	p.Received += rx
	if r.Sent > 0 && r.Received > 0 && p.FirstExchange.IsZero() {
		p.FirstExchange = time.Now()
		p.FirstExchangeMS = p.FirstExchange.Sub(p.Started).Milliseconds()
	}
	s.paths[r.Owner.Profile] = p
}
