package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

func timeoutFixture(t *testing.T) (*Controller, profilesResult) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	return c, profilesResult{profile: profiles.Profile{ID: "chrome-x"}, network: "net-1", enabled: true}
}

func enableYouTubeRelay(c *Controller) {
	c.mu.Lock()
	c.settings.YouTubeViaRelay = true
	c.mu.Unlock()
}

var directPlan = browserproxy.Plan{Policy: flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen}}

func TestTwoConnectTimeoutsSteerOriginToRelayFailClosed(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "Ordinary.Example", Port: 443, Secure: true}
	now := time.Now()
	if _, steered := c.steerTimedOutOrigin(directPlan, cur, q, now); steered {
		t.Fatal("steered before any timeout")
	}
	c.observeDirectOpen(cur, q, directPlan, context.DeadlineExceeded, now)
	if _, steered := c.steerTimedOutOrigin(directPlan, cur, q, now); steered {
		t.Fatal("a single timeout must not steer")
	}
	c.observeDirectOpen(cur, q, directPlan, fmt.Errorf("dial: %w", context.DeadlineExceeded), now.Add(30*time.Second))
	plan, steered := c.steerTimedOutOrigin(directPlan, cur, q, now.Add(31*time.Second))
	if !steered {
		t.Fatal("two timeouts within 60 s did not steer")
	}
	p := plan.Policy
	if p.Action != flowpolicy.RelayRequired || p.Fallback != flowpolicy.Required || p.RelayID != "VPS-01" || p.Source != "direct_timeout_cache" || plan.Probe != "DIRECT_TIMEOUT_CACHED" {
		t.Fatalf("not relay-first fail-closed: %+v probe=%s", p, plan.Probe)
	}
	// A different network, application or host never inherits the cache.
	other := cur
	other.network = "net-2"
	if _, steered := c.steerTimedOutOrigin(directPlan, other, q, now.Add(32*time.Second)); steered {
		t.Fatal("cache leaked across networks")
	}
	if _, steered := c.steerTimedOutOrigin(directPlan, cur, browserproxy.Request{Host: "example.org", Port: 443}, now.Add(32*time.Second)); steered {
		t.Fatal("cache leaked across hosts")
	}
}

func TestOnlyConnectDeadlinesOnOrdinaryDirectOriginsCount(t *testing.T) {
	c, cur := timeoutFixture(t)
	now := time.Now()
	count := func(q browserproxy.Request, plan browserproxy.Plan, err error) {
		for i := 0; i < 3; i++ {
			c.observeDirectOpen(cur, q, plan, err, now.Add(time.Duration(i)*time.Second))
		}
	}
	ordinary := browserproxy.Request{Host: "a.example", Port: 443}
	count(ordinary, directPlan, context.Canceled)
	count(ordinary, directPlan, errors.New("connection refused"))
	count(browserproxy.Request{Host: "203.0.113.7", Port: 443}, directPlan, context.DeadlineExceeded)                                                                      // IP literal
	count(browserproxy.Request{Host: "chatgpt.com", Port: 443}, directPlan, context.DeadlineExceeded)                                                                      // protected
	count(browserproxy.Request{Host: "www.youtube.com", Port: 443}, browserproxy.Plan{Policy: flowpolicy.Result{Action: flowpolicy.DirectPlus}}, context.DeadlineExceeded) // DIRECT+ owns YouTube
	relayPlan := browserproxy.Plan{Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}
	count(ordinary, relayPlan, context.DeadlineExceeded) // relay timeouts say nothing about DIRECT
	if s := c.browser.directTimeouts.Stats(); s.ActiveOrigins != 0 || s.Created != 0 {
		t.Fatalf("ineligible events were cached: %+v", s)
	}
	// A TCP ACK alone is not an HTTP success and must not clear the verdict.
	c.observeDirectOpen(cur, ordinary, directPlan, context.DeadlineExceeded, now)
	c.observeDirectOpen(cur, ordinary, directPlan, nil, now.Add(time.Second))
	c.observeDirectOpen(cur, ordinary, directPlan, context.DeadlineExceeded, now.Add(2*time.Second))
	if _, steered := c.steerTimedOutOrigin(directPlan, cur, ordinary, now.Add(3*time.Second)); !steered {
		t.Fatal("bare TCP ACK erased the failure verdict")
	}
}

func TestCacheHitsAreVisibleInBrowserStatus(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "ordinary.example", Port: 443, Secure: true}
	now := time.Now()
	c.observeDirectOpen(cur, q, directPlan, context.DeadlineExceeded, now)
	c.observeDirectOpen(cur, q, directPlan, context.DeadlineExceeded, now.Add(time.Second))
	for i := 0; i < 4; i++ {
		c.steerTimedOutOrigin(directPlan, cur, q, now.Add(2*time.Second))
	}
	status, err := c.Handle(context.Background(), "browser.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(status)
	var out struct {
		Cache struct {
			Active int    `json:"active_origins"`
			Hits   uint64 `json:"relay_steered_flows"`
			Top    []struct {
				Host string `json:"host"`
				Hits uint64 `json:"relay_steered_flows"`
			} `json:"top_origins"`
		} `json:"direct_timeout_cache"`
		Records json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Cache.Active != 1 || out.Cache.Hits != 4 || len(out.Cache.Top) != 1 || out.Cache.Top[0].Host != "ordinary.example" || !strings.Contains(string(out.Records), "[") {
		t.Fatalf("%s", raw)
	}
}

// The recheck runs once per TTL in the background. When it cannot conclude (here the
// browser owner is gone) traffic stays on the relay and the recheck is retried soon.
func TestBackgroundRecheckKeepsRelayWhenInconclusiveAndRetries(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "ordinary.example", Port: 443, Secure: true}
	now := time.Now()
	c.observeDirectOpen(cur, q, directPlan, context.DeadlineExceeded, now)
	c.observeDirectOpen(cur, q, directPlan, context.DeadlineExceeded, now.Add(time.Second))
	later := now.Add(flowpolicy.DirectTimeoutTTL + 2*time.Second)
	plan, steered := c.steerTimedOutOrigin(directPlan, cur, q, later)
	if !steered || plan.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal("traffic left the relay while the recheck was due")
	}
	key := c.directTimeoutKey(cur, q)
	deadline := time.Now().Add(5 * time.Second)
	for {
		// After the inconclusive probe finished, the short retry backoff applies.
		if _, due := c.browser.directTimeouts.Lookup(key, time.Now().Add(2*time.Minute)); due {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background recheck never finished or was never rescheduled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s := c.browser.directTimeouts.Stats(); s.ActiveOrigins != 1 || s.Revalidations < 2 {
		t.Fatalf("%+v", s)
	}
}

func TestTwoStallsMakeYouTubeAndItsVideoHostsRelayFirstWithoutLeakingToDirect(t *testing.T) {
	c, cur := timeoutFixture(t)
	enableYouTubeRelay(c)
	now := time.Now()
	key := func(host string) flowpolicy.DirectTimeoutKey {
		return c.directTimeoutKey(cur, browserproxy.Request{Host: host, Port: 443, Secure: true})
	}
	// Every googlevideo edge node shares one entry; ordinary YouTube hosts keep their own.
	if key("rr3---sn-4g5e6nzs.googlevideo.com") != key("rr9---sn-abcd1234.googlevideo.com.") || key("www.youtube.com") == key("www.google.com") {
		t.Fatal("cache key folding wrong")
	}
	node1 := browserproxy.Request{Host: "rr3---sn-4g5e6nzs.googlevideo.com", Port: 443, Secure: true}
	node2 := browserproxy.Request{Host: "rr9---sn-abcd1234.googlevideo.com", Port: 443, Secure: true}
	c.browser.directTimeouts.RecordStall(c.directTimeoutKey(cur, node1), now)
	if _, ok := c.steerTimedOutOrigin(directPlan, cur, node2, now); ok {
		t.Fatal("a single stall steered traffic")
	}
	c.browser.directTimeouts.RecordStall(c.directTimeoutKey(cur, node2), now.Add(20*time.Second))
	for _, q := range []browserproxy.Request{node1, node2, {Host: "rr1---sn-zzzz.googlevideo.com", Port: 443, Secure: true}} {
		plan, ok := c.steerTimedOutOrigin(directPlan, cur, q, now.Add(30*time.Second))
		if !ok || plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
			t.Fatalf("%s not relay-first fail-closed: %+v", q.Host, plan.Policy)
		}
	}
	// YouTube with DIRECT+ configured is not touched by the cache.
	dp := browserproxy.Plan{Policy: flowpolicy.Result{Action: flowpolicy.DirectPlus, Strategy: "yt"}}
	if _, ok := c.steerTimedOutOrigin(dp, cur, node1, now.Add(31*time.Second)); ok {
		t.Fatal("the cache overrode a DIRECT+ plan")
	}
	if s := c.browser.directTimeouts.Stats(); s.Stalls != 2 || s.ActiveOrigins != 1 {
		t.Fatalf("%+v", s)
	}
}

// A stalled path still completes the TCP connect. Only the origin's first byte proves DIRECT works.
func TestConnectAndUnverifiedTLSFirstByteDoNotClearFailureVerdict(t *testing.T) {
	c, cur := timeoutFixture(t)
	enableYouTubeRelay(c)
	q := browserproxy.Request{Host: "www.youtube.com", Port: 443, Secure: true}
	now := time.Now()
	c.browser.directTimeouts.RecordStall(c.directTimeoutKey(cur, q), now)
	c.observeDirectOpen(cur, q, directPlan, nil, now.Add(time.Second)) // connect succeeds on a blackholing path
	c.browser.directTimeouts.RecordStall(c.directTimeoutKey(cur, q), now.Add(2*time.Second))
	if _, ok := c.steerTimedOutOrigin(directPlan, cur, q, now.Add(3*time.Second)); !ok {
		t.Fatal("a successful TCP connect between two stalls must not reset the count")
	}
	// A TLS alert, one byte or handshake alone cannot prove a working HTTPS site.
	c.recordAnswered(cur, q, directPlan)
	if _, ok := c.steerTimedOutOrigin(directPlan, cur, q, now.Add(4*time.Second)); !ok {
		t.Fatal("an unverified first byte erased the failure verdict")
	}
}

func TestStallRetryPlanIsRelayRequiredFailClosedAndNeverDirect(t *testing.T) {
	_, cur := timeoutFixture(t)
	plan := stallRetryPlan(cur, directPlan)
	if plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required || plan.Policy.RelayID != "VPS-01" || plan.Policy.Source != "direct_stall_retry" {
		t.Fatalf("%+v", plan.Policy)
	}
	for _, host := range []string{"chatgpt.com", "api.openai.com"} {
		if directTimeoutEligible(browserproxy.Request{Host: host, Port: 443}, directPlan) {
			t.Fatalf("%s is protected and relay-required from the start; the stall path must not touch it", host)
		}
	}
}

// Without youtube_via_relay YouTube is never moved to the relay, but stalls are still counted.
func TestYouTubeFallbackDoesNotDependOnRelayFirstPreference(t *testing.T) {
	c, cur := timeoutFixture(t)
	now := time.Now()
	yt := browserproxy.Request{Host: "rr3---sn-4g5e6nzs.googlevideo.com", Port: 443, Secure: true}
	other := browserproxy.Request{Host: "example.com", Port: 443, Secure: true}
	for _, q := range []browserproxy.Request{yt, other} {
		c.browser.directTimeouts.RecordStall(c.directTimeoutKey(cur, q), now)
		c.browser.directTimeouts.RecordStall(c.directTimeoutKey(cur, q), now.Add(time.Second))
	}
	if _, ok := c.steerTimedOutOrigin(directPlan, cur, yt, now.Add(2*time.Second)); !ok {
		t.Fatal("YouTube fallback incorrectly depends on flag")
	}
	if _, ok := c.steerTimedOutOrigin(directPlan, cur, other, now.Add(2*time.Second)); !ok {
		t.Fatal("a non-YouTube origin must not depend on the YouTube flag")
	}
	opened := false
	open := func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		opened = true
		return nil, errors.New("must not open")
	}
	if _, _, err := c.stallRetry(context.Background(), cur, yt, directPlan, open); err == nil || !opened {
		t.Fatalf("fallback must attempt relay with flag off: err=%v opened=%v", err, opened)
	}
	if s := c.browser.directTimeouts.Stats(); s.Stalls != 5 || s.StallRetries != 0 {
		t.Fatalf("%+v", s)
	}
	enableYouTubeRelay(c)
	if _, ok := c.steerTimedOutOrigin(directPlan, cur, yt, now.Add(2*time.Second)); !ok {
		t.Fatal("YouTube not steered with the flag on")
	}
}

func TestYouTubeViaRelaySettingSurvivesSettingsSetAndPersists(t *testing.T) {
	var s Settings
	if err := json.Unmarshal([]byte(`{"automatic":true,"failover":"DIRECT","update_channel":"stable","youtube_via_relay":true}`), &s); err != nil || !s.YouTubeViaRelay {
		t.Fatalf("%+v %v", s, err)
	}
	if b, _ := json.Marshal(Settings{Failover: "DIRECT", UpdateChannel: "stable"}); strings.Contains(string(b), "youtube") {
		t.Fatalf("default must stay out of settings.json: %s", b)
	}
}

func TestYouTubeFirstClientHelloStallPromotesDomainWithoutAnotherDirectAddress(t *testing.T) {
	for _, host := range []string{"www.youtube.com", "r.googlevideo.com", "i.ytimg.com"} {
		c, cur := timeoutFixture(t)
		q := browserproxy.Request{Host: host, Port: 443, Secure: true}
		calls := 0
		_, actual, _ := c.stallRetry(context.Background(), cur, q, boundedDirectPlan(), func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			calls++
			if p.Policy.Action != flowpolicy.RelayRequired {
				t.Fatal("redundant DIRECT SNI retry")
			}
			return nil, errors.New("test relay unavailable")
		})
		if calls != 1 || actual.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal(calls, actual)
		}
		if _, ok := c.steerTimedOutOrigin(boundedDirectPlan(), cur, q, time.Now()); !ok {
			t.Fatal("first stall did not promote domain", host)
		}
		other := cur
		other.network = "another-network"
		if _, ok := c.steerTimedOutOrigin(boundedDirectPlan(), other, q, time.Now()); ok {
			t.Fatal("cross-network verdict")
		}
	}
}
