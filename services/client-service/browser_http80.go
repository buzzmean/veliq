package clientservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
)

const http80LadderSource = "http80_local_ladder"
const http80ProofTTL = 5 * time.Minute
const http80Retry = 3 * time.Minute

type http80Key struct {
	Network, Profile, Revision, Host, Address, Executable string
	PID                                                   uint32
	Birth                                                 uint64
}
type http80Entry struct {
	id                 string
	engine             *localstrategy.LocalStrategyEngine
	until, retry, used time.Time
	generation         uint64
}
type http80Snapshot struct {
	Entries    int    `json:"entries"`
	Active     bool   `json:"active"`
	Attempts   uint64 `json:"attempts"`
	Upgrades   uint64 `json:"upgrades"`
	Failures   uint64 `json:"failures"`
	Cancelled  uint64 `json:"cancelled"`
	LocalOpens uint64 `json:"local_opens"`
	RelayOpens uint64 `json:"relay_opens"`
}
type http80Runtime struct {
	mu      sync.Mutex
	entries map[http80Key]*http80Entry
	workers sync.WaitGroup
	stopped bool
	stats   http80Snapshot
}
type http80ContextKey struct{}
type http80Scope struct {
	current  profilesResult
	request  browserproxy.Request
	plan     browserproxy.Plan
	revision string
}

func newHTTP80Runtime() *http80Runtime { return &http80Runtime{entries: map[http80Key]*http80Entry{}} }
func (r *http80Runtime) stop()         { r.mu.Lock(); r.stopped = true; r.mu.Unlock(); r.workers.Wait() }
func (r *http80Runtime) snapshot() http80Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	s.Entries = len(r.entries)
	return s
}
func (r *http80Runtime) engine(id string) *localstrategy.LocalStrategyEngine {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.id == id {
			return e.engine
		}
	}
	return nil
}

func (c *Controller) http80Eligible(cur profilesResult, q browserproxy.Request, p browserproxy.Plan) bool {
	if !cur.enabled || cur.routingDisabled || !browserAuto(cur.profile) || !p.Enabled || p.Network != cur.network || !q.Source.IsValid() || q.Source.Addr().IsUnspecified() || q.Source.Port() == 0 || q.Ingress != "NATIVE_TCP" || q.Secure || q.Port != 80 || q.HintOnly || q.OriginAmbiguous || p.Destination.Port() != 80 || !p.Destination.Addr().Is4() || !browserproxy.PublicDNSAddress(p.Destination.Addr()) || !browserproxy.ValidPublicDNSName(q.Host) || protectedBrowserDomain(q.Host) || c.browserOriginPolicy(q.Host).Kind != "DPI" || p.Policy.Action == flowpolicy.Block || p.Policy.Source == "rule" || p.Policy.Source == "configured_baseline" || p.Policy.Action == flowpolicy.RelayRequired && p.Policy.Source == "" {
		return false
	}
	_, explicit := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: p.Destination, Domain: q.Host, Network: cur.network})
	return !explicit
}
func (c *Controller) http80ScopeCurrent(s http80Scope, fresh profilesResult) bool {
	return fresh.network == s.current.network && c.policyRevision(fresh.profile) == s.revision && c.youtubeLocalAllowed(fresh.network) && c.http80Eligible(fresh, s.request, s.plan)
}
func (c *Controller) http80Current(s http80Scope) bool {
	fresh, err := c.browserProfile(s.request.Owner)
	return err == nil && c.http80ScopeCurrent(s, fresh)
}
func (c *Controller) http80Entry(s http80Scope) (http80Key, *http80Entry) {
	k := http80Key{s.current.network, s.current.profile.ID, s.revision, s.request.Host, s.plan.Destination.String(), s.request.Owner.Exe, s.request.Owner.PID, s.request.Owner.Birth}
	r := c.browser.http80
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if r.stopped {
		return k, nil
	}
	if e := r.entries[k]; e != nil {
		e.used = now
		return k, e
	}
	for key, e := range r.entries {
		if now.Sub(e.used) > 30*time.Minute {
			delete(r.entries, key)
		}
	}
	if len(r.entries) >= 128 {
		return k, nil
	}
	raw, _ := json.Marshal(k)
	sum := sha256.Sum256(raw)
	id := "http80-" + hex.EncodeToString(sum[:12])
	engine := localstrategy.New()
	p := localstrategy.Profile{ID: id, Name: "HTTP80 Host split", Version: 1, Protocol: "tcp", Ports: []uint16{80}, Application: k.Executable, Domains: []string{k.Host}, Strategy: localstrategy.HTTP80HostSplit, Cutoff: 1, Enabled: true}
	if engine.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{p}}) != nil {
		return k, nil
	}
	engine.Guard = func(m localstrategy.Metadata) bool {
		return m.Destination == s.plan.Destination && strings.EqualFold(m.Domain, s.request.Host) && c.http80Current(s)
	}
	e := &http80Entry{id: id, engine: engine, used: now}
	r.entries[k] = e
	return k, e
}
func (r *http80Runtime) failed(k http80Key, e *http80Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries[k] != e {
		return
	}
	e.generation++ // An older probe cannot erase a newer actual flow failure.
	e.until = time.Time{}
	e.retry = time.Now().Add(http80Retry)
	r.stats.Failures++
}
func http80LocalPlan(p browserproxy.Plan, e *http80Entry) browserproxy.Plan {
	p.DirectCandidates, p.RelayCandidates = nil, nil
	p.FirstFlightManaged = true
	p.Probe = "HTTP80_HTTPS_UPGRADE_OBSERVED"
	p.Policy = flowpolicy.Result{Action: flowpolicy.DirectPlus, Strategy: e.id, Source: http80LadderSource, Fallback: flowpolicy.FailBlock, Reason: "HTTP80 same-host upgrade observed with committed Host split; no TLS/page proof; no replay"}
	return p
}

func (c *Controller) http80Recheck(s http80Scope, k http80Key, e *http80Entry) {
	if e == nil || !c.http80Current(s) {
		return
	}
	r := c.browser.http80
	r.mu.Lock()
	now := time.Now()
	if r.stopped || r.stats.Active || r.entries[k] != e || now.Before(e.until) || now.Before(e.retry) {
		r.mu.Unlock()
		return
	}
	select {
	case c.browser.probes <- struct{}{}:
	default:
		r.mu.Unlock()
		return
	}
	r.stats.Active = true
	r.stats.Attempts++
	e.generation++
	generation := e.generation
	e.retry = now.Add(http80Retry)
	r.workers.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.workers.Done()
		defer func() { <-c.browser.probes; r.mu.Lock(); r.stats.Active = false; r.mu.Unlock() }()
		ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
		defer cancel()
		ctx = context.WithValue(ctx, http80ContextKey{}, s)
		plan := http80LocalPlan(s.plan, e)
		_, reason := browserproxy.ProbeHTTP80Upgrade(ctx, s.request.Host, func(ctx context.Context) (net.Conn, error) { return c.browserOpenUnobserved(ctx, s.request, plan) }, func() bool { return c.browserTransform(s.request, plan) })
		current := c.http80Current(s) && !errors.Is(ctx.Err(), context.Canceled)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.entries[k] != e || e.generation != generation {
			return
		}
		if !current {
			e.retry = time.Time{}
			r.stats.Cancelled++
			return
		}
		if reason == "HTTP80_HTTPS_UPGRADE_OBSERVED" {
			e.until = time.Now().Add(http80ProofTTL)
			r.stats.Upgrades++
		} else {
			r.stats.Failures++
		}
	}()
}

func (c *Controller) openHTTP80Plan(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	s := http80Scope{current: cur, request: q, plan: p, revision: c.policyRevision(cur.profile)}
	k, e := c.http80Entry(s)
	r := c.browser.http80
	r.mu.Lock()
	local := e != nil && time.Now().Before(e.until)
	r.mu.Unlock()
	// A cold request stays on RELAY even if its independent probe finishes now.
	c.http80Recheck(s, k, e)
	if local && c.http80Current(s) {
		plan := http80LocalPlan(p, e)
		attempt, cancel := context.WithTimeout(context.WithValue(ctx, http80ContextKey{}, s), time.Second)
		conn, err := open(attempt, q, plan)
		cancel()
		if err == nil {
			r.mu.Lock()
			r.stats.LocalOpens++
			r.mu.Unlock()
			var once sync.Once
			failed := func() { once.Do(func() { r.failed(k, e) }) }
			first := &nativeFirstReplyConn{Conn: conn, timeout: 1500 * time.Millisecond, failed: func(string) { failed() }}
			return &http80Conn{Conn: browserproxy.WatchMidstream(first, 6*time.Second, failed), failed: failed, plan: plan}, plan, nil
		}
		if c.http80Current(s) {
			r.failed(k, e)
		} else {
			return nil, plan, err
		}
	}
	plan := stallRetryPlan(cur, p)
	plan.DirectCandidates, plan.RelayCandidates = nil, nil
	plan.FirstFlightManaged, plan.Probe, plan.Policy.Source = true, "HTTP80_RELAY_WHILE_UNPROVEN", http80LadderSource
	conn, err := open(ctx, q, plan)
	if err == nil {
		r.mu.Lock()
		r.stats.RelayOpens++
		r.mu.Unlock()
	}
	return conn, plan, err
}

// Only future opens consume transport failures. No dial/retry function or
// retained application payload is available to replay an established request.
type http80Conn struct {
	net.Conn
	failed func()
	plan   browserproxy.Plan
	closed atomic.Bool
}

func (c *http80Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	var timeout net.Error
	if err != nil && !c.closed.Load() && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !(errors.As(err, &timeout) && timeout.Timeout()) {
		c.failed()
	}
	return n, err
}
func (c *http80Conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil && !c.closed.Load() {
		c.failed()
	}
	return n, err
}
func (c *http80Conn) Close() error { c.closed.Store(true); return c.Conn.Close() }
func (c *http80Conn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func (c *http80Conn) CurrentPlan() browserproxy.Plan              { return c.plan }
func (c *http80Conn) CurrentTCPPolicy() (flowpolicy.Result, bool) { return c.plan.Policy, true }
