package clientservice

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/optimizer"
)

const automaticTLSLocalSource = "automatic_tls_local"
const automaticTLSFallbackSource = "automatic_tls_relay"
const automaticTLSLocalCandidate = "split1"

type automaticLocalPlan struct {
	key       localstrategy.TargetKey
	candidate string
	confirmed bool
}

func (c *Controller) automaticTLSLocalPlan(cur profilesResult, q browserproxy.Request, p browserproxy.Plan) automaticLocalPlan {
	if !localBrowserRequestEligible(q, p) || q.HintOnly || !c.youtubeLocalAllowed(cur.network) ||
		c.browserOriginPolicy(q.Host).Kind == "RELAY" || browserproxy.KnownDoHEndpoint(q.Host, p.Destination) {
		return automaticLocalPlan{}
	}
	candidate := automaticTLSLocalCandidate
	revision := cur.automaticRevision
	if c.catalog != nil && c.browserOriginPolicy(q.Host).Kind == "DPI" {
		catalog := c.catalog.snapshot()
		if len(catalog.Plans) != 0 {
			candidate = catalog.Plans[0].ID
		}
	}
	key := localstrategy.TargetKey{
		ConfigRevision: revision, Network: cur.network, Application: applicationKey(cur.profile),
		Destination: p.Destination.String(), Domain: strings.ToLower(strings.TrimSuffix(q.Host, ".")),
		Protocol: "tcp", Version: localstrategy.Version,
	}
	now := time.Now()
	known, seen := c.browser.automaticTLSLocal.Evidence(key, candidate, now)
	if seen && known.FailureCount != 0 {
		return automaticLocalPlan{}
	}
	return automaticLocalPlan{key: key, candidate: candidate, confirmed: seen && !known.LastSuccess.IsZero()}
}

func (c *Controller) recoverAutomaticTLS(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error), local automaticLocalPlan, reason string) (net.Conn, browserproxy.Plan, error) {
	// Try a healthy DNS peer before experimenting with the original endpoint.
	// The existing stepper bounds DNS, alternate DIRECT and ClientHello replay.
	if c.browserOriginPolicy(q.Host).Kind == "" {
		return c.openOrdinaryAddressesWithFallback(ctx, cur, q, p, open, func(work context.Context, current profilesResult, request browserproxy.Request, original browserproxy.Plan, dial func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
			return c.openAutomaticTLSLocal(work, current, request, original, dial, local, reason)
		})
	}
	return c.openAutomaticTLSLocal(ctx, cur, q, p, open, local, reason)
}

func (c *Controller) openAutomaticTLSLocal(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error), local automaticLocalPlan, reason string) (net.Conn, browserproxy.Plan, error) {
	relay := func(work context.Context, why string) (net.Conn, browserproxy.Plan, error) {
		if err := work.Err(); err != nil {
			return nil, p, err
		}
		if !c.automaticScopeCurrent(cur) {
			return nil, p, errAutomaticScopeChanged
		}
		actual := stallRetryPlan(cur, p)
		actual.Policy.Source, actual.Policy.Reason = automaticTLSFallbackSource, why
		actual.Probe = "AUTOMATIC_TLS_RELAY"
		actual.FirstFlightManaged = true
		conn, err := open(work, q, actual)
		return conn, actual, err
	}
	if err := ctx.Err(); err != nil {
		return nil, p, err
	}
	if !c.automaticScopeCurrent(cur) {
		return nil, p, errAutomaticScopeChanged
	}
	if local.candidate == "" {
		return relay(ctx, reason+"; LOCAL_UNAVAILABLE_OR_DENIED")
	}
	latest := c.automaticTLSLocalPlan(cur, q, p)
	if latest.candidate == "" || latest.candidate != local.candidate {
		return relay(ctx, reason+"; LOCAL_SELECTION_CHANGED")
	}
	local = latest
	actual := p
	if strings.HasPrefix(local.candidate, "catalog-") && c.catalog != nil {
		c.browser.youtube.setPlans(c.catalog.snapshot().Plans)
	}
	id, _ := c.youtubeEngine(cur, q, actual, local.candidate)
	if id == "" {
		return relay(ctx, reason+"; LOCAL_STRATEGY_UNAVAILABLE")
	}
	actual.Policy = flowpolicy.Result{Action: flowpolicy.DirectPlus, Strategy: id, Fallback: flowpolicy.FailBlock, Source: automaticTLSLocalSource, Reason: reason + "; " + local.candidate}
	actual.Probe = "AUTOMATIC_TLS_LOCAL"
	actual.FirstFlightManaged = true

	var release func()
	if !local.confirmed {
		select {
		case c.browser.automaticTLSLocalProbes <- struct{}{}:
			release = func() { <-c.browser.automaticTLSLocalProbes }
		default:
			return relay(ctx, reason+"; LOCAL_PROBE_CAPACITY")
		}
	}
	started := time.Now()
	attempt, cancel := context.WithTimeout(ctx, 550*time.Millisecond)
	conn, err := open(attempt, q, actual)
	cancel()
	recordFailure := func() {
		if !c.automaticScopeCurrent(cur) || !c.youtubeLocalAllowed(cur.network) {
			return
		}
		now := time.Now()
		_ = c.browser.automaticTLSLocal.Record(local.key, local.candidate, optimizer.RouteMeasurement{ObservedAt: now}, false, now)
	}
	if err != nil || conn == nil {
		if release != nil {
			release()
		}
		if conn != nil {
			_ = conn.Close()
		}
		if ctx.Err() != nil {
			return nil, actual, ctx.Err()
		}
		if !c.automaticScopeCurrent(cur) || errors.Is(err, errAutomaticScopeChanged) {
			return nil, actual, errAutomaticScopeChanged
		}
		if retryableDirectOpen(err) {
			recordFailure()
			return relay(ctx, "LOCAL_CONNECT_FAILED")
		}
		// A local permission/queue/configuration error does not diagnose the endpoint.
		// After an already proven DIRECT failure, relay is still permitted.
		if !local.confirmed {
			return relay(ctx, "LOCAL_OPEN_UNAVAILABLE")
		}
		if err == nil {
			err = errors.New("AUTOMATIC_LOCAL_OPEN_UNAVAILABLE")
		}
		return nil, actual, err
	}
	observer := &automaticTLSLocalConn{Conn: conn, release: release, started: started}
	observer.confirmed = func(elapsed time.Duration) {
		if !c.automaticScopeCurrent(cur) || !c.youtubeLocalAllowed(cur.network) || !c.browserTransform(q, actual) {
			return
		}
		now := time.Now()
		_ = c.browser.automaticTLSLocal.Record(local.key, local.candidate, optimizer.RouteMeasurement{
			RouteID: local.candidate, RTT: elapsed, Available: true, Samples: 1, Stability: 1, ObservedAt: now,
		}, true, now)
	}
	ref := &youtubePlanRef{}
	ref.set(actual, observer)
	watched := browserproxy.WatchRelayOrigin(observer, browserproxy.OriginConfig{
		Context: c.ctx, Health: browserproxy.NewOriginHealth(), Initial: actual.Destination, Silence: browserproxy.OriginSilenceTimeout,
		ScopeCurrent: func() bool { return c.automaticScopeCurrent(cur) },
		OnFailure: func(failure string) {
			if automaticNetworkFailure(failure) {
				recordFailure()
			}
		},
		NextFlow: func(work context.Context, failure string) (net.Conn, error) {
			next, actual, err := relay(work, "LOCAL_"+failure)
			if err == nil {
				ref.set(actual, next)
			}
			return next, err
		},
	})
	return &youtubePlanConn{Conn: watched, ref: ref}, actual, nil
}

// LOCAL selection may reuse exact transport proof. This meter observes TLS
// record framing only and does not diagnose HTTP, authentication or region.
type automaticTLSLocalConn struct {
	net.Conn
	wire        browserproxy.TLSWireObserver
	postHello   atomic.Bool
	once, freed sync.Once
	confirmed   func(time.Duration)
	started     time.Time
	release     func()
}

func (c *automaticTLSLocalConn) Write(p []byte) (int, error) {
	afterHello := c.wire.Snapshot().Origin.ServerHelloComplete
	n, err := c.Conn.Write(p)
	if n > 0 && afterHello {
		c.postHello.Store(true)
	}
	return n, err
}

func (c *automaticTLSLocalConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.wire.ObserveOrigin(p[:n])
	tls := c.wire.Snapshot().Origin
	if tls.ServerHelloComplete {
		c.releaseSlot()
		if tls.ApplicationBytes >= 64*1024 && c.postHello.Load() {
			c.once.Do(func() { c.confirmed(time.Since(c.started)) })
		}
	}
	return n, err
}

func (c *automaticTLSLocalConn) Close() error {
	c.releaseSlot()
	return c.Conn.Close()
}

func (c *automaticTLSLocalConn) releaseSlot() {
	if c.release != nil {
		c.freed.Do(c.release)
	}
}

func (c *automaticTLSLocalConn) CloseWrite() error {
	if upstream, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return upstream.CloseWrite()
	}
	return nil
}
