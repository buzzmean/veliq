package clientservice

import (
	"context"
	"crypto/ed25519"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/locallearning"
	"sort"
	"strings"
	"sync"
	"time"
)

type sharedLearningRow struct {
	Profile   string    `json:"profile"`
	Group     string    `json:"group"`
	Network   string    `json:"network_cohort"`
	Candidate string    `json:"candidate,omitempty"`
	Picker    bool      `json:"picker"`
	State     string    `json:"state"`
	Until     time.Time `json:"until"`
}
type sharedLearningSnapshot struct {
	Entries   int                 `json:"entries"`
	Omitted   int                 `json:"rows_omitted"`
	State     string              `json:"state"`
	LastError string              `json:"last_error,omitempty"`
	LastCheck time.Time           `json:"last_check"`
	Scope     string              `json:"scope"`
	Rows      []sharedLearningRow `json:"rows"`
}
type sharedLearningEntry struct {
	doc                locallearning.Document
	reported, rejected string
	checked            time.Time
}
type browserSharedLearning struct {
	mu         sync.Mutex
	configured bool
	started    time.Time
	status     sharedLearningSnapshot
	entries    map[youtubeKey]sharedLearningEntry
	wake       chan struct{}
}

func newSharedLearning() *browserSharedLearning {
	return &browserSharedLearning{entries: map[youtubeKey]sharedLearningEntry{}, wake: make(chan struct{}, 1), status: sharedLearningSnapshot{State: "CP_NOT_CONNECTED", Scope: "advisory candidates only; public-prefix HMAC cohort; no hardware/user identifiers; local confirmation mandatory"}}
}
func (s *browserSharedLearning) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *browserSharedLearning) snapshot() sharedLearningSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.status
	v.Entries = len(s.entries)
	v.Rows = []sharedLearningRow{}
	for k, e := range s.entries {
		if len(v.Rows) >= 24 {
			break
		}
		v.Rows = append(v.Rows, sharedLearningRow{k.Profile, k.Domain, e.doc.Network, e.doc.Candidate, e.doc.Picker, e.doc.State, e.doc.ExpiresAt})
	}
	v.Omitted = v.Entries - len(v.Rows)
	return v
}
func (s *browserSharedLearning) decision(k youtubeKey, now time.Time) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configured {
		return true, ""
	}
	e, ok := s.entries[k]
	if ok && now.Before(e.doc.ExpiresAt) {
		if e.doc.Candidate != "" && now.Before(e.doc.CandidateUntil) && e.rejected != e.doc.Candidate {
			return true, e.doc.Candidate
		}
		return e.doc.Picker, ""
	}
	if s.status.State == "CP_UNAVAILABLE_LOCAL_FALLBACK" {
		return true, ""
	}
	if s.status.State == "SIGNED_SHARED_LEARNING" {
		return false, ""
	}
	// Hold the initial picker briefly for a response, then fail to bounded local
	// selection. A CP outage must not make previously working traffic unusable.
	return now.Sub(s.started) > 5*time.Second, ""
}
func (s *browserSharedLearning) reject(k youtubeKey, candidate string) {
	s.mu.Lock()
	e := s.entries[k]
	if e.doc.Candidate == candidate {
		e.rejected = candidate
	}
	if _, ok := s.entries[k]; ok {
		s.entries[k] = e
	}
	s.mu.Unlock()
	s.notify()
}
func (s *browserSharedLearning) accept(k youtubeKey, doc locallearning.Document, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[k]; !ok && len(s.entries) >= 256 {
		for key, v := range s.entries {
			if now.Sub(v.checked) > 24*time.Hour {
				delete(s.entries, key)
			}
		}
		if len(s.entries) >= 256 {
			return false
		}
	}
	e := s.entries[k]
	if e.doc.Network == doc.Network && !e.doc.GeneratedAt.IsZero() && doc.GeneratedAt.Before(e.doc.GeneratedAt) {
		return false
	}
	if e.doc.Network == doc.Network && now.Before(e.doc.ExpiresAt) && doc.Version < e.doc.Version {
		return false
	}
	if e.doc.Candidate != doc.Candidate {
		e.reported = ""
		e.rejected = ""
	}
	e.doc = doc
	e.checked = now
	s.entries[k] = e
	s.status.State = "SIGNED_SHARED_LEARNING"
	s.status.LastError = ""
	s.status.LastCheck = now
	return true
}
func (c *Controller) runSharedLearning(ctx context.Context, cp *controlclient.Client, keys map[string]ed25519.PublicKey) {
	r := c.browser.youtube
	s := r.shared
	s.mu.Lock()
	s.configured = true
	s.started = time.Now()
	s.status.State = "WAITING_FOR_SIGNED_COHORT"
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.configured = false
		s.status.State = "CP_DISCONNECTED_LOCAL_FALLBACK"
		s.mu.Unlock()
	}()
	var lastRequest time.Time
	poll := func() {
		r.mu.Lock()
		pending := make(map[youtubeKey]youtubeLearn)
		for k := range r.pending {
			pending[k] = r.cache[k]
		}
		r.mu.Unlock()
		list := make([]youtubeKey, 0, len(pending))
		for k := range pending {
			list = append(list, k)
		}
		s.mu.Lock()
		sort.Slice(list, func(i, j int) bool { return s.entries[list[i]].checked.Before(s.entries[list[j]].checked) })
		s.mu.Unlock()
		if len(list) > 16 {
			list = list[:16]
		}
		for _, k := range list {
			if ctx.Err() != nil {
				return
			}
			cmd := locallearning.Command{Scope: locallearning.Scope{Group: k.Domain, HintOnly: k.HintOnly}, Action: "observe"}
			if !locallearning.ValidScope(cmd.Scope) || !c.sharedScopeAllowed(k) {
				continue
			}
			v := pending[k]
			s.mu.Lock()
			prior := s.entries[k]
			s.mu.Unlock()
			verifiedLocal := v.Confirmed && v.Stage == "LOCAL" && v.VerifiedBytes > 64*1024 && time.Now().Before(v.Until)
			if youtubeCDN(k) && v.Streak < youtubeTrialSuccesses {
				verifiedLocal = false
			}
			interval := 30 * time.Second
			if !prior.doc.Picker {
				interval = 2 * time.Minute
			}
			if verifiedLocal && prior.doc.Candidate == v.Strategy {
				interval = 5 * time.Minute
			}
			urgent := verifiedLocal && prior.doc.Picker && prior.reported != v.Strategy
			if !urgent && time.Since(prior.checked) < interval {
				continue
			}
			if verifiedLocal && prior.doc.Picker && prior.reported != v.Strategy {
				cmd.Action = "report"
				cmd.Candidate = v.Strategy
				cmd.Applied = true
				cmd.BodyBytes = v.VerifiedBytes
				cmd.Flows = v.Streak
				if cmd.Flows == 0 {
					cmd.Flows = 1
				}
			} else if prior.doc.Picker && prior.doc.Candidate != "" && prior.rejected == prior.doc.Candidate {
				cmd.Action = "reject"
				cmd.Candidate = prior.doc.Candidate
			}
			// Forty PCs behind one NAT must not burst background coordination into
			// the existing auth/ticket rate limit. Foreground traffic never waits.
			if pause := time.Until(lastRequest.Add(2 * time.Second)); pause > 0 {
				timer := time.NewTimer(pause)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			lastRequest = time.Now()
			work, cancel := context.WithTimeout(ctx, 2*time.Second)
			raw, err := cp.LocalLearning(work, cmd)
			cancel()
			now := time.Now()
			if err != nil {
				s.mu.Lock()
				e := s.entries[k]
				e.checked = now
				s.entries[k] = e
				s.status.State = "CP_UNAVAILABLE_LOCAL_FALLBACK"
				s.status.LastError = "SHARED_LEARNING_CP_UNAVAILABLE_OR_UNSUPPORTED; bounded per-PC selection continues"
				s.status.LastCheck = now
				s.mu.Unlock()
				continue
			}
			doc, err := locallearning.Validate(keys, raw, cmd.Scope, now)
			if err != nil || !s.accept(k, doc, now) {
				s.mu.Lock()
				s.status.LastError = "SHARED_LEARNING_SIGNATURE_SCOPE_TTL_OR_ROLLBACK_REJECTED"
				s.mu.Unlock()
				continue
			}
			if cmd.Action == "report" {
				s.mu.Lock()
				e := s.entries[k]
				e.reported = cmd.Candidate
				s.entries[k] = e
				s.mu.Unlock()
			}
		}
	}
	timer := time.NewTicker(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			poll()
		case <-timer.C:
			poll()
		}
	}
}

func (c *Controller) sharedScopeAllowed(k youtubeKey) bool {
	host := k.Domain
	if strings.HasPrefix(host, "googlevideo:") {
		host = "googlevideo.com"
	}
	return c.browserOriginPolicy(host).Kind == "DPI"
}
