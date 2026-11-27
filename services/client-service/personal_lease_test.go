package clientservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

type stageLeaseServer struct {
	mu                  sync.Mutex
	owner, id           string
	expires             time.Time
	ttl                 time.Duration
	renewError          bool
	supported, required bool
}
type stageLeaseDevice struct {
	server *stageLeaseServer
	device string
}

func (d stageLeaseDevice) SubscriptionStatus(context.Context) (controlclient.SubscriptionStatus, error) {
	d.server.mu.Lock()
	defer d.server.mu.Unlock()
	return controlclient.SubscriptionStatus{Managed: true, Active: true, Enforced: true, OptimizationLease: controlclient.OptimizationLeasePolicy{Supported: d.server.supported, Required: d.server.required, TTLSeconds: 60, RenewAfterSeconds: 20}}, nil
}
func (d stageLeaseDevice) OptimizationLease(_ context.Context, action, id string) (controlclient.OptimizationLease, error) {
	s := d.server
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	reply := controlclient.OptimizationLease{Supported: s.supported, Required: s.required, ServerTime: now}
	if action == "release" {
		if s.owner == d.device && s.id == id {
			s.owner = ""
			s.id = ""
		}
		return reply, nil
	}
	if action == "renew" && s.renewError {
		return reply, errors.New("fixture network outage")
	}
	if action == "renew" && (s.owner != d.device || s.id != id || !now.Before(s.expires)) {
		return reply, nil
	}
	if s.owner != "" && now.Before(s.expires) && s.owner != d.device {
		return reply, nil
	}
	if s.owner == "" || !now.Before(s.expires) {
		s.id = fmt.Sprintf("%032d", len(d.device))
		s.owner = d.device
	}
	s.expires = now.Add(s.ttl)
	expires := s.expires
	reply.Granted = true
	reply.LeaseID = s.id
	reply.ExpiresAt = &expires
	return reply, nil
}
func personalLeaseController(t *testing.T, source personalLeaseSource) (*Controller, *activationCaptureFixture) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.Backend = &activationCaptureFixture{}
	if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
		t.Fatal(err)
	}
	c.configurePersonalLeaseStage(true)
	c.setPersonalLeaseSource(source)
	c.Start()
	return c, c.Backend.(*activationCaptureFixture)
}
func optimizeStage(c *Controller, enabled bool) error {
	_, err := c.Handle(c.ctx, "optimize", []byte(fmt.Sprintf(`{"enabled":%t}`, enabled)))
	return err
}

func TestPersonalStageLeaseAdmitsOneOptimizationAndReleasesAfterOff(t *testing.T) {
	s := &stageLeaseServer{ttl: 60 * time.Second, supported: true, required: true}
	a, ab := personalLeaseController(t, stageLeaseDevice{s, "a"})
	b, bb := personalLeaseController(t, stageLeaseDevice{s, "bb"})
	if err := optimizeStage(a, true); err != nil {
		t.Fatal(err)
	}
	if err := optimizeStage(a, true); err != nil {
		t.Fatal("idempotent same client", err)
	}
	if err := optimizeStage(b, true); err == nil || bb.active.Load() {
		t.Fatal("second optimization admitted", err)
	}
	if !ab.active.Load() || !a.activationNetworkAllowed() {
		t.Fatal("owner stopped by competing client")
	}
	if err := optimizeStage(a, false); err != nil {
		t.Fatal(err)
	}
	if ab.active.Load() {
		t.Fatal("lease released before optimization stopped")
	}
	if err := optimizeStage(b, true); err != nil || !bb.active.Load() {
		t.Fatal("next sequential computer denied", err)
	}
	if a.activationNetworkAllowed() {
		t.Fatal("old computer retained admission after release")
	}
}

func TestPersonalStageLeaseConcurrentOptimizationHasOneWinner(t *testing.T) {
	s := &stageLeaseServer{ttl: 60 * time.Second, supported: true, required: true}
	a, ab := personalLeaseController(t, stageLeaseDevice{s, "a"})
	b, bb := personalLeaseController(t, stageLeaseDevice{s, "bb"})
	start := make(chan struct{})
	answers := make(chan error, 2)
	for _, c := range []*Controller{a, b} {
		go func(c *Controller) { <-start; answers <- optimizeStage(c, true) }(c)
	}
	close(start)
	winners := 0
	for range 2 {
		if <-answers == nil {
			winners++
		}
	}
	if winners != 1 || ab.active.Load() == bb.active.Load() {
		t.Fatalf("winners=%d captures=%t/%t", winners, ab.active.Load(), bb.active.Load())
	}
}

func TestPersonalStageLeaseUnsupportedCannotStartButLegacyIsUnchanged(t *testing.T) {
	s := &stageLeaseServer{supported: false}
	c, b := personalLeaseController(t, stageLeaseDevice{s, "a"})
	if err := optimizeStage(c, true); err == nil || b.starts.Load() != 0 {
		t.Fatal("unsupported stage started capture", err)
	}
	legacy, lb := subscriptionController(t)
	if err := optimizeStage(legacy, true); err != nil || !lb.active.Load() {
		t.Fatal("non opted-in legacy changed", err)
	}
}

func TestPersonalStageLeaseExpiryStopsCaptureWithoutSuccessfulRenewal(t *testing.T) {
	s := &stageLeaseServer{ttl: 2500 * time.Millisecond, supported: true, required: true, renewError: true}
	c, b := personalLeaseController(t, stageLeaseDevice{s, "a"})
	if err := optimizeStage(c, true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for b.active.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b.active.Load() || c.activationNetworkAllowed() {
		t.Fatal("expired lease kept optimizing")
	}
	if c.personalLeaseView().State != "RELEASED" && c.personalLeaseView().State != "EXPIRED" {
		t.Fatal(c.personalLeaseView())
	}
}

func TestPersonalStageLeaseDeadlineDoesNotExtendForSlowResponseOrClockSkew(t *testing.T) {
	start := time.Now()
	server := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := server.Add(60 * time.Second)
	reply := controlclient.OptimizationLease{Supported: true, Required: true, Granted: true, LeaseID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ServerTime: server, ExpiresAt: &expiry}
	deadline, err := personalLeaseDeadline(reply, start, start.Add(40*time.Second))
	if err != nil || !deadline.Equal(start.Add(59*time.Second)) {
		t.Fatal(deadline, err)
	}
	if _, err := personalLeaseDeadline(reply, start, start.Add(60*time.Second)); err == nil {
		t.Fatal("response arriving after deadline reopened access")
	}
	expiry = server.Add(61 * time.Second)
	if _, err := personalLeaseDeadline(reply, start, start); err == nil {
		t.Fatal("unbounded TTL accepted")
	}
}

type blockedRenewSource struct {
	stageLeaseDevice
	entered chan struct{}
	resume  chan struct{}
}

func (s blockedRenewSource) OptimizationLease(ctx context.Context, action, id string) (controlclient.OptimizationLease, error) {
	if action == "renew" {
		close(s.entered)
		select {
		case <-s.resume:
		case <-ctx.Done():
			return controlclient.OptimizationLease{}, ctx.Err()
		}
	}
	return s.stageLeaseDevice.OptimizationLease(ctx, action, id)
}

func TestPersonalStageLeaseLateRenewCannotReopenExpiredOptimization(t *testing.T) {
	s := &stageLeaseServer{ttl: 60 * time.Second, supported: true, required: true}
	resume := make(chan struct{})
	defer close(resume)
	source := blockedRenewSource{stageLeaseDevice: stageLeaseDevice{s, "a"}, entered: make(chan struct{}), resume: resume}
	c, b := personalLeaseController(t, source)
	if err := optimizeStage(c, true); err != nil {
		t.Fatal(err)
	}
	c.personalLease.mu.Lock()
	c.personalLease.deadline = time.Now().Add(600 * time.Millisecond)
	c.personalLease.renewAt = time.Now()
	c.personalLease.mu.Unlock()
	select {
	case <-source.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("renew did not start")
	}
	deadline := time.Now().Add(2 * time.Second)
	for b.active.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b.active.Load() || c.activationNetworkAllowed() {
		t.Fatal("blocking renewal extended expired optimization")
	}
	// Unblock a successful response whose server-side lease is still valid: the
	// controller generation must reject it after local expiry, without restarting.
	source.resume <- struct{}{}
	deadline = time.Now().Add(time.Second)
	for c.personalLease.renewing.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if b.active.Load() || c.activationNetworkAllowed() {
		t.Fatal("late renewal reopened admission")
	}
}

func TestPersonalStageLeaseRebindSuspendsCaptureWithoutOldLeaseID(t *testing.T) {
	s := &stageLeaseServer{ttl: 60 * time.Second, supported: true, required: true}
	c, b := personalLeaseController(t, stageLeaseDevice{s, "a"})
	if err := optimizeStage(c, true); err != nil {
		t.Fatal(err)
	}
	c.setPersonalLeaseSource(stageLeaseDevice{s, "bb"})
	deadline := time.Now().Add(2 * time.Second)
	for b.active.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if b.active.Load() || c.activationNetworkAllowed() {
		t.Fatal("source reset left unleased capture active")
	}
	if err := optimizeStage(c, true); err == nil {
		t.Fatal("other identity took over old lease before TTL")
	}
}

func TestPersonalStageLeaseEffectiveClassificationKeepsHealthyUnselectedDirect(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.enabled = true
	c.configurePersonalLeaseStage(true)
	id := wp.ProcessIdentity{PID: 16036, CreationTime: 134402359570643174, Path: `C:\Games\Warhammer\warhammer 40000 space marine 2 - retail.exe`}
	tuple := destTuple("tcp", "93.184.216.34", 443)
	d := wp.ResolveDeferredDecision(c.Classify(id, tuple), "ordinary.example.org", "REASSEMBLY_COMPLETE")
	if d.Block || !d.Route.Direct() || d.Route.Local() || d.Policy.Action != flowpolicy.Direct {
		t.Fatal("healthy unselected game changed", d)
	}
	protected := wp.ResolveDeferredDecision(c.Classify(id, tuple), "chatgpt.com", "REASSEMBLY_COMPLETE")
	if !protected.Block || !protected.BlockOnFailure || protected.Policy.Action != flowpolicy.Block || protected.Policy.Source != "personal_lease_required" {
		t.Fatal("protected new admission escaped expired lease", protected)
	}
	for _, mode := range []profiles.Mode{profiles.Manual, profiles.DirectPlus, profiles.Direct} {
		p := profiles.Profile{ID: "stage-managed", Name: "Stage", Executables: []string{id.Path}, Mode: mode, RelayID: "VPS-01", Custom: true}
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
		d := c.Classify(id, tuple)
		if mode == profiles.Direct {
			if d.Block || !d.Route.Direct() {
				t.Fatal("explicit DIRECT blocked", d)
			}
		} else if !d.Block || d.Policy.Source != "personal_lease_required" {
			t.Fatal("managed optimization admitted", mode, d)
		}
	}
	for _, tuple := range []wp.Tuple{destTuple("tcp", "192.168.1.10", 3260), destTuple("udp", "1.1.1.1", 53)} {
		if d := c.Classify(id, tuple); d.Block || !d.Route.Direct() {
			t.Fatal("LAN/DNS blocked", d)
		}
	}
}

func TestPersonalStageLeaseProxyAdmissionDeniesOptimizationButNotPlainDirect(t *testing.T) {
	c, cur := timeoutFixture(t)
	c.configurePersonalLeaseStage(true)
	for _, action := range []flowpolicy.Action{flowpolicy.RelayRequired, flowpolicy.DirectPlus} {
		calls := 0
		p := boundedDirectPlan()
		p.Policy.Action = action
		_, _, err := c.openBrowserPlan(c.ctx, cur, browserproxy.Request{Host: "chatgpt.com", Port: 443}, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
			calls++
			return nil, nil
		})
		if err == nil || calls != 0 {
			t.Fatal("expired optimization reached upstream", action, calls, err)
		}
	}
	calls := 0
	p := boundedDirectPlan()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn, actual, err := c.openBrowserPlan(c.ctx, cur, browserproxy.Request{Host: "ordinary.example.org", Port: 443}, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		calls++
		return a, nil
	})
	if err != nil || conn != a || calls != 1 || actual.Policy.Action != flowpolicy.Direct {
		t.Fatal("plain healthy DIRECT did not remain available", actual, calls, err)
	}
}

func TestPersonalStageLeaseExpiredImplicitTLSUsesPlainDirectDespiteCachedLocal(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	c.Backend = &youtubeTransformFixture{}
	local := c.automaticTLSLocalPlan(cur, q, p)
	if local.candidate == "" {
		t.Fatal("LOCAL cache fixture unavailable")
	}
	now := time.Now()
	if err := c.browser.automaticTLSLocal.Record(local.key, local.candidate, optimizer.RouteMeasurement{ObservedAt: now, Available: true, Samples: 3, Stability: 1, RTT: time.Millisecond}, true, now); err != nil {
		t.Fatal(err)
	}
	if !c.automaticTLSLocalPlan(cur, q, p).confirmed {
		t.Fatal("fixture did not establish cached LOCAL")
	}
	c.configurePersonalLeaseStage(true) // No lease: the cached optimization is unavailable.
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	calls := 0
	conn, actual, err := c.openAutomaticPlan(c.ctx, cur, q, p, func(ctx context.Context, _ browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		calls++
		if actual.Policy.Action != flowpolicy.Direct || actual.FirstFlightManaged {
			t.Errorf("expired lease used optimization %+v", actual)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	automaticTLSExchange(t, conn, q, roots)
	if calls != 1 || actual.Policy.Action != flowpolicy.Direct {
		t.Fatal("healthy direct exchange changed", calls, actual)
	}
}

func TestPersonalStageLeaseExpiredSnapshotDoesNotClaimOptimizingBeforeWorkerTick(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.Demo = true
	c.enabled = true
	c.configurePersonalLeaseStage(true)
	c.personalLease.mu.Lock()
	c.personalLease.known = true
	c.personalLease.required = true
	c.personalLease.id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	c.personalLease.deadline = time.Now().Add(-time.Second)
	c.personalLease.mu.Unlock()
	if s := c.Snapshot(); s.Optimizing || s.CapturePermitted {
		t.Fatal("expired admission advertised optimization before cleanup tick", s.Optimizing, s.CapturePermitted)
	}
	legacy := New(context.Background())
	defer legacy.Close()
	legacy.Demo = true
	legacy.enabled = true
	if !legacy.Snapshot().Optimizing {
		t.Fatal("default-off snapshot changed")
	}
}
