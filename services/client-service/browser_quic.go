package clientservice

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/originpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

type browserQUICRecord struct {
	At        time.Time `json:"at"`
	Host      string    `json:"host"`
	Outcome   string    `json:"outcome"`
	Observed  bool      `json:"observed"`
	BodyBytes uint64    `json:"body_bytes"`
}
type browserQUICRuntime struct {
	mu                           sync.Mutex
	manager                      *browserproxy.HTTP3ProbeManager
	workers                      sync.WaitGroup
	active, closed               bool
	next                         time.Time
	retry                        map[browserproxy.HTTP3ProbeKey]time.Time
	records                      []browserQUICRecord
	attempts, observed, canceled uint64
}

func newBrowserQUICRuntime() *browserQUICRuntime {
	return &browserQUICRuntime{manager: browserproxy.NewHTTP3ProbeManager(), retry: make(map[browserproxy.HTTP3ProbeKey]time.Time)}
}
func (r *browserQUICRuntime) close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.manager.Close()
	r.workers.Wait()
}
func (r *browserQUICRuntime) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{"scope": "OWNED_HTTP3_PROBES_ONLY; no browser LOCAL admission", "active": r.active, "attempts": r.attempts, "observed": r.observed, "canceled": r.canceled, "records": append([]browserQUICRecord{}, r.records...)}
}
func (r *browserQUICRuntime) submit(ctx context.Context, k browserproxy.HTTP3ProbeKey, claim func() bool, current func(browserproxy.HTTP3ProbeKey) bool, open func(context.Context) (browserproxy.HTTP3ProbeSocket, error), roots *x509.CertPool, slots chan struct{}, now time.Time) bool {
	// No OS calls, DNS or network work in this entrypoint: it runs on capture's
	// packet loop. The worker rechecks the real owner/SID and policy before open.
	if ctx.Err() != nil || originpolicy.Floor(k.Host).Kind != "DPI" || !browserproxy.ValidPublicDNSName(k.Host) || claim == nil || current == nil || open == nil {
		return false
	}
	r.mu.Lock()
	if r.closed || r.active || now.Before(r.next) || now.Before(r.retry[k]) {
		r.mu.Unlock()
		return false
	}
	for key, until := range r.retry {
		if !now.Before(until) {
			delete(r.retry, key)
		}
	}
	if len(r.retry) >= 128 {
		r.mu.Unlock()
		return false
	}
	select {
	case slots <- struct{}{}:
	default:
		r.mu.Unlock()
		return false
	}
	if !claim() {
		<-slots
		r.mu.Unlock()
		return false
	}
	r.active = true
	r.next = now.Add(30 * time.Second)
	r.attempts++
	r.workers.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.workers.Done()
		defer func() { <-slots; r.mu.Lock(); r.active = false; r.mu.Unlock() }()
		result := r.manager.Probe(ctx, k, roots, current, open)
		r.mu.Lock()
		defer r.mu.Unlock()
		neutral := result.Outcome == "HTTP3_SCOPE_CHANGED" || result.Outcome == "HTTP3_CANCELED_OR_TIMEOUT" || result.Outcome == "HTTP3_MANAGER_CLOSED"
		if neutral {
			r.canceled++
		} else {
			ttl := 3 * time.Minute
			if result.Observed {
				r.observed++
				ttl = 5 * time.Minute
			}
			r.retry[k] = time.Now().Add(ttl)
		}
		// Historical observations only; no CID, SID, endpoint handle or payload.
		if len(r.records) == 16 {
			r.records = r.records[1:]
		}
		r.records = append(r.records, browserQUICRecord{At: time.Now(), Host: k.Host, Outcome: result.Outcome, Observed: result.Observed, BodyBytes: result.BodyBytes})
	}()
	return true
}

func (c *Controller) browserQUICDecision(p profiles.Profile, id wp.ProcessIdentity, t wp.Tuple, d wp.Decision) wp.Decision {
	if t.Protocol != "udp" || t.Destination.Port() != 443 || !nativeBrowserProfile(p) || p.Mode != profiles.Auto || !d.Block || d.Policy.Source != "browser_native_quic_tcp_fallback" {
		return d
	}
	network, revision, profile := d.Network, d.Revision, p.ID
	d.QUICProbe = func(trigger wp.QUICProbeTrigger) {
		k := trigger.Key()
		if k.PID != id.PID || k.Birth != id.CreationTime || k.Executable != id.Path || trigger.BrowserTuple() != t || k.Endpoint != t.Destination || k.Network != network || k.Profile != profile || k.Revision != revision {
			return
		}
		sid := c.BrowserOwnerSID // Installation owner is immutable for this controller.
		current := func(key browserproxy.HTTP3ProbeKey) bool {
			if key != k || !trigger.Current() || !c.browserQUICCurrent(k, id, sid) {
				return false
			}
			return true
		}
		open := func(ctx context.Context) (browserproxy.HTTP3ProbeSocket, error) {
			scope := wp.QUICProbeScope{Owner: id, Destination: k.Endpoint, Network: network, Profile: profile, Revision: revision}
			return wp.OpenQUICProbeSocket(ctx, scope, 6, func(s wp.QUICProbeScope) bool {
				return s.Owner == id && s.Destination == k.Endpoint && s.Network == network && s.Profile == profile && s.Revision == revision && current(k)
			})
		}
		c.browser.quic.submit(c.ctx, k, trigger.Claim, current, open, c.BrowserProbeRoots, c.browser.probes, time.Now())
	}
	return d
}

func (c *Controller) browserQUICCurrent(k browserproxy.HTTP3ProbeKey, id wp.ProcessIdentity, sid string) bool {
	if k.PID != id.PID || k.Birth != id.CreationTime || k.Executable != id.Path || c.ctx.Err() != nil || !wp.CurrentQUICProcessOwner(id, sid) {
		return false
	}
	cur, err := c.browserProfile(browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: k.Profile})
	if err != nil || !cur.enabled || cur.network != k.Network || !nativeBrowserProfile(cur.profile) || c.policyRevision(cur.profile) != k.Revision || !c.browserLocalAllowed(k.Network) || !c.nativeBackendReady() {
		return false
	}
	policy := c.browserOriginPolicy(k.Host)
	if policy.Kind != "DPI" || policy.Protected {
		return false
	}
	_, explicit := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "udp", Destination: k.Endpoint, Domain: k.Host, Network: k.Network})
	return !explicit
}
