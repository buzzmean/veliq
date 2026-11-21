package flowpolicy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// BrowserLearning consumes actual HTTP(S) completion evidence, never TCP ACKs,
// passive RTT or reachability of another origin. It schedules NEW attempts only.
// The caller must correlate the observation with the captured immutable route.
type BrowserLearning struct {
	mu      sync.Mutex
	entries map[LearnKey]BrowserAttempt
}
type BrowserAttempt struct {
	BrowserTrial bool      `json:"browser_trial_unverified,omitempty"`
	Key          LearnKey  `json:"key"`
	Token        string    `json:"token"`
	Route        Result    `json:"route"`
	Stage        int       `json:"stage"`
	Confirmed    bool      `json:"confirmed"`
	Outcome      string    `json:"outcome"`
	HTTPStatus   int       `json:"http_status,omitempty"`
	Destination  string    `json:"destination,omitempty"`
	Started      time.Time `json:"started"`
	Expires      time.Time `json:"expires"`
	RetryAfter   time.Time `json:"retry_after"`
}
type BrowserObservation struct {
	Token        string
	HTTPStatus   int
	NetworkError string
	OriginTLS    bool
	// Correlated is established only by the service after exact origin/flow checks.
	Correlated    bool
	Destination   string
	ResponseBytes uint64
}

func NewBrowserLearning() *BrowserLearning {
	return &BrowserLearning{entries: make(map[LearnKey]BrowserAttempt)}
}
func browserKeyValid(k LearnKey) bool {
	if k.Network == "" || len(k.Network) > 128 || k.Application == "" || len(k.Application) > 2048 || k.Protocol != "tcp" || k.Port == 0 || len(k.Target) == 0 || len(k.Target) > 253 || k.Target != strings.ToLower(k.Target) {
		return false
	}
	for _, label := range strings.Split(k.Target, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func browserToken() (string, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}
func (b *BrowserLearning) cleanup(now time.Time) {
	for k, v := range b.entries {
		if !now.Before(v.Expires) {
			delete(b.entries, k)
		}
	}
}
func browserCandidate(stage int, strategy, relay string) Result {
	r := Result{Action: Direct, Fallback: FailOpen, Source: "browser_trial", Reason: "origin DIRECT trial; HTTP result pending"}
	if stage == 1 {
		r.Action = DirectPlus
		r.Strategy = strategy
		r.Reason = "origin DIRECT+ trial after correlated DIRECT network failure"
	}
	if stage == 2 {
		r.Action = RelayRequired
		r.RelayID = relay
		r.Fallback = Required
		r.Reason = "origin authenticated relay trial after local route failures"
	}
	return r
}
func (b *BrowserLearning) Begin(k LearnKey, strategy, relay string, now time.Time) (BrowserAttempt, error) {
	if !browserKeyValid(k) || relay == "" || len(strategy) > 64 || len(relay) > 128 {
		return BrowserAttempt{}, errors.New("invalid bounded browser origin key")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanup(now)
	if v, ok := b.entries[k]; ok {
		return v, nil
	}
	if len(b.entries) >= 512 {
		return BrowserAttempt{}, errors.New("browser origin capacity")
	}
	token, err := browserToken()
	if err != nil {
		return BrowserAttempt{}, err
	}
	v := BrowserAttempt{Key: k, Token: token, Route: browserCandidate(0, strategy, relay), Started: now, Expires: now.Add(2 * time.Minute), Outcome: "HTTP_PENDING"}
	b.entries[k] = v
	return v, nil
}
func (b *BrowserLearning) Lookup(k LearnKey, now time.Time) (BrowserAttempt, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanup(now)
	v, ok := b.entries[k]
	return v, ok
}
func (b *BrowserLearning) Observe(k LearnKey, observation BrowserObservation, strategy, relay string, now time.Time) (BrowserAttempt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanup(now)
	v, ok := b.entries[k]
	if !ok || v.Token != observation.Token || !observation.Correlated || now.Before(v.Started) || !now.Before(v.Expires) {
		return BrowserAttempt{}, errors.New("stale or uncorrelated browser observation")
	}
	if !v.RetryAfter.IsZero() && now.Before(v.RetryAfter) {
		return v, errors.New("browser origin cooldown")
	}
	if observation.HTTPStatus >= 200 && observation.HTTPStatus < 400 && observation.NetworkError == "" && observation.ResponseBytes > 0 {
		v.Destination = observation.Destination
		v.Confirmed = true
		v.HTTPStatus = observation.HTTPStatus
		v.Outcome = "HTTP_SUCCESS"
		v.Expires = now.Add(15 * time.Minute)
		v.Route.Source = "browser_http_verified"
		v.Route.Reason = "bounded origin HTTP(S) response on this domain/network; browser page unverified"
	} else if (observation.HTTPStatus >= 400 && observation.HTTPStatus <= 599 && observation.NetworkError == "") || observation.NetworkError == "TLS_CERTIFICATE_ERROR" {
		// Authentication/WAF/server errors are not proof that a different egress is
		// needed. Do not turn 403 into a successful trial or repeatedly replay login.
		v.Confirmed = false
		v.HTTPStatus = observation.HTTPStatus
		v.Outcome = "HTTP_APPLICATION_ERROR"
		if observation.NetworkError == "TLS_CERTIFICATE_ERROR" {
			v.Outcome = observation.NetworkError
		}
		v.RetryAfter = now.Add(time.Minute)
		v.Expires = v.RetryAfter
	} else {
		switch observation.NetworkError {
		case "NETWORK_TIMEOUT", "CONNECTION_RESET", "CONNECTION_FAILED", "TLS_FAILED", "DNS_FAILED", "NO_TRANSFORM", "TRANSFORM_APPLIED_CONNECTION_FAILED":
		default:
			return v, errors.New("not an application-level browser result")
		}
		v.Confirmed = false
		v.Outcome = observation.NetworkError
		if v.Stage >= 2 {
			v.RetryAfter = now.Add(time.Minute)
			// The authenticated OPEN succeeded, but our independent Go ClientHello
			// failed. It cannot veto Chrome's different TLS fingerprint. Offer a NEW
			// browser relay tunnel, explicitly unverified, never a healthy cache result.
			if observation.OriginTLS && observation.NetworkError == "TLS_FAILED" {
				v.BrowserTrial = true
				v.Destination = observation.Destination
				v.Outcome = "ORIGIN_TLS_BROWSER_TRIAL_UNVERIFIED"
				v.Route.Source = "browser_tls_trial_unverified"
				v.Route.Reason = "local routes failed; relay OPEN succeeded; browser TLS result unverified"
				v.RetryAfter = now.Add(5 * time.Second)
			}
			v.Expires = v.RetryAfter
		} else {
			v.Stage++
			if v.Stage == 1 && strategy == "" {
				v.Stage = 2
			}
			v.Route = browserCandidate(v.Stage, strategy, relay)
			token, err := browserToken()
			if err != nil {
				return v, err
			}
			v.Token = token
			v.Started = now
			v.Expires = now.Add(2 * time.Minute)
		}
	}
	b.entries[k] = v
	return v, nil
}

// Invalidate a learned origin if its pinned address disappeared from DNS. An IP
// chosen on one lookup must never be silently replaced under a confirmed route.
func (b *BrowserLearning) Forget(k LearnKey) { b.mu.Lock(); delete(b.entries, k); b.mu.Unlock() }
