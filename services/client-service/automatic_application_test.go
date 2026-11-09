package clientservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestAutomaticDiscoveryNeedsNoUserProfileAndKeepsExplicitChoices(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled = true
	before := len(c.Profiles.List())
	id := wp.ProcessIdentity{PID: 99, CreationTime: 10, Path: `C:\Apps\NeverRegistered\client.exe`}
	d := c.Classify(id, destTuple("tcp", "93.184.216.34", 443))
	if !d.Deferred || d.OpenDeferred == nil || !d.NewConnectionsOnly || !d.Route.Direct() || d.Flow.PinnedPolicy == nil || d.Flow.ApplicationID == "" {
		t.Fatalf("automatic capture missing: %+v", d)
	}
	preferGameRelay(c)
	resolved := wp.ResolveDeferredDecision(d, "ordinary.example.org", "REASSEMBLY_COMPLETE")
	if !resolved.Route.Direct() || len(c.Profiles.List()) != before {
		t.Fatal("global probe score or registry mutation", resolved)
	}
	other, _ := discoveredApplication(wp.ProcessIdentity{PID: 100, CreationTime: 20, Path: `c:/apps/neverregistered/CLIENT.exe`})
	if d.Flow.ApplicationID != other.ID {
		t.Fatal("PID/case changed application scope")
	}
	for _, mode := range []profiles.Mode{profiles.Direct, profiles.Manual, profiles.Block} {
		p := profiles.Profile{ID: "choice", Name: "Choice", Executables: []string{id.Path}, Mode: mode, RelayID: "VPS-01", Custom: true}
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
		v := c.Classify(id, destTuple("tcp", "93.184.216.34", 443))
		if v.OpenDeferred != nil || v.Flow.ApplicationID != p.ID {
			t.Fatal("explicit mode overridden", mode, v)
		}
	}
	c.Profiles.Delete("choice")
	c.settings.Automatic = false
	if v := c.Classify(id, destTuple("tcp", "93.184.216.34", 443)); v.Deferred || v.OpenDeferred != nil || !v.Route.Direct() {
		t.Fatal("disabled automation captures", v)
	}
}

func TestAutomaticDiscoveryDoesNotCaptureDNSLANUnknownOwnersOrExistingBrowserLane(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled = true
	id := wp.ProcessIdentity{PID: 20, CreationTime: 10, Path: `C:\Apps\new.exe`}
	for _, tuple := range []wp.Tuple{destTuple("tcp", "192.168.1.1", 443), destTuple("tcp", "10.0.0.1", 3260), destTuple("tcp", "127.0.0.1", 8080), destTuple("tcp", "1.1.1.1", 53), destTuple("udp", "1.1.1.1", 53), destTuple("udp", "51.38.142.176", 27015), destTuple("udp", "8.8.8.8", 443), destTuple("tcp", "2001:4860:4860::8888", 443)} {
		v := c.Classify(id, tuple)
		if v.Deferred || v.OpenDeferred != nil || v.ProbeDirect || v.Block || !v.Route.Direct() {
			t.Fatal("excluded traffic captured", tuple, v)
		}
	}
	for _, identity := range []wp.ProcessIdentity{{PID: 20, Path: id.Path}, {PID: 20, CreationTime: 10}, {PID: 20, CreationTime: 10, Path: "new.exe"}, {PID: 20, CreationTime: 10, Path: `C:\Browser\chrome.exe`}, {PID: 20, CreationTime: 10, Path: `C:\Browser\msedge.exe`}} {
		v := c.Classify(identity, destTuple("tcp", "8.8.8.8", 443))
		if v.Deferred || v.OpenDeferred != nil {
			t.Fatal("unverified owner/browser lane captured", identity, v)
		}
	}
	c.selfExecutable = id.Path
	if v := c.Classify(id, destTuple("tcp", "8.8.8.8", 443)); v.Deferred || v.OpenDeferred != nil {
		t.Fatal("self captured")
	}
}

func TestAutomaticGeminiAndProtectedServiceFloorWithoutExecutableRegistration(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled = true
	id := wp.ProcessIdentity{PID: 21, CreationTime: 12, Path: `C:\Apps\api-client.exe`}
	for _, host := range []string{"gemini.google.com", "generativelanguage.googleapis.com", "chatgpt.com", "claude.ai"} {
		v := wp.ResolveDeferredDecision(c.Classify(id, destTuple("tcp", "8.8.8.8", 443)), host, "REASSEMBLY_COMPLETE")
		if v.Policy.Action != flowpolicy.RelayRequired || v.Route.RelayID != "VPS-01" || !v.BlockOnFailure || v.Flow.PinnedPolicy == nil {
			t.Fatal(host, v)
		}
		if _, err := c.Engine.OpenTCP(context.Background(), v.Flow); err == nil {
			t.Fatal("unavailable relay leaked", host)
		}
	}
}

func automaticFixture(t *testing.T) (*Controller, profilesResult, browserproxy.Request, browserproxy.Plan) {
	t.Helper()
	c, cur, q, p := youtubeFixture(t)
	c.enabled, c.settings.Automatic = true, true
	id := wp.ProcessIdentity{PID: 77, CreationTime: 11, Path: `C:\Apps\new-api-client.exe`}
	profile, _ := discoveredApplication(id)
	cur.profile, cur.id = profile, id
	q.Owner = browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: profile.ID}
	q.Ingress, q.Host, q.Secure = "AUTOMATIC_TCP", "ordinary.example.org", true
	p.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Source: "auto_direct_default", Fallback: flowpolicy.FailOpen}
	return c, c.captureAutomaticScope(cur), q, p
}

func TestAutomaticHealthyTLSDoesNotProbeOrOpenRelay(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "healthy") }))
	var opens atomic.Int32
	raw, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		opens.Add(1)
		if plan.Policy.Action != flowpolicy.Direct {
			t.Error("healthy app relayed")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://"+q.Host+"/", nil)
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "healthy" || opens.Load() != 1 {
		t.Fatal(string(body), err, opens.Load())
	}
}

func TestAutomaticSilentTLSRecoversBeforeApplicationPayload(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "recovered") }))
	var direct, relay atomic.Int32
	raw, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action == flowpolicy.Direct {
			direct.Add(1)
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(io.Discard, b) }()
			return a, nil
		}
		if plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
			t.Error("invalid fallback", plan)
		}
		relay.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if direct.Load() != 1 || relay.Load() != 1 || !c.directAddressFailed(cur, q, p) {
		t.Fatal(direct.Load(), relay.Load())
	}
	if got := raw.(browserproxy.PlanReporter).CurrentPlan(); got.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal(got)
	}
}

func TestAutomaticSocketFallbackIsScopedExpiresAndNeverReplaysPayload(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	q.Host, q.Port, q.Secure = "", 5222, false
	p.Destination = netip.AddrPortFrom(p.Destination.Addr(), 5222)
	var actions []flowpolicy.Action
	open := func(_ context.Context, _ browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		actions = append(actions, actual.Policy.Action)
		if actual.Policy.Action == flowpolicy.Direct {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	for i := 0; i < 2; i++ {
		conn, actual, err := c.openAutomaticPlan(context.Background(), cur, q, p, open)
		if err != nil || actual.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal(err, actual)
		}
		conn.Write([]byte("non-idempotent message"))
		conn.Close()
	}
	if len(actions) != 3 || actions[0] != flowpolicy.Direct || actions[1] != flowpolicy.RelayRequired || actions[2] != flowpolicy.RelayRequired {
		t.Fatal(actions)
	}
	key := c.directTimeoutKey(cur, q, p)
	key.Host = p.Destination.Addr().String()
	if c.browser.directTimeouts.AddressFailed(key, time.Now().Add(11*time.Minute)) {
		t.Fatal("permanent relay")
	}
	for _, mutate := range []func(*flowpolicy.DirectTimeoutKey){func(k *flowpolicy.DirectTimeoutKey) { k.Network = "other" }, func(k *flowpolicy.DirectTimeoutKey) { k.Application = "other" }, func(k *flowpolicy.DirectTimeoutKey) { k.Port++ }, func(k *flowpolicy.DirectTimeoutKey) { k.Address = "1.1.1.1" }} {
		other := key
		mutate(&other)
		if c.browser.directTimeouts.AddressFailed(other, time.Now()) {
			t.Fatal("scope leaked", other)
		}
	}
	actions = nil
	// A new network is a fresh, authenticated scope, not an old snapshot with
	// only its display label changed.
	fresh := cur
	fresh.network = "new-network"
	network := *c.network.Load()
	network.Fingerprint = fresh.network
	c.network.Store(&network)
	p.Network = fresh.network
	_, _, err := c.openAutomaticPlan(context.Background(), fresh, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		actions = append(actions, flowpolicy.Direct)
		return nil, context.Canceled
	})
	if !errors.Is(err, context.Canceled) || len(actions) != 1 {
		t.Fatal("cancellation learned or relayed", err, actions)
	}
}

func TestAutomaticStatusIsDispatchedAndHasExplicitCoverage(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	v, err := c.Handle(context.Background(), "automation.status", nil)
	if err != nil || v.(map[string]any)["scope"] == "" {
		t.Fatal(v, err)
	}
	if !clubReadMethod("automation.status") {
		t.Fatal("club diagnostics unavailable")
	}
}

func TestAutomaticPlanningFailureIsNotNetworkEvidence(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	calls := 0
	_, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		calls++
		return nil, errors.New("AUTOMATIC_SCOPE_CHANGED")
	})
	if err == nil || calls != 1 || c.directAddressFailed(cur, q, p) {
		t.Fatal("policy error learned as network failure", err, calls)
	}
}

func TestAutomaticTLSOriginAlertForbidsReplay(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	var calls atomic.Int32
	raw, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		calls.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			buf := make([]byte, 8192)
			b.Read(buf)
			b.Write([]byte{21, 3, 3, 0, 2, 2, 40})
		}()
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	secure := tls.Client(raw, &tls.Config{ServerName: q.Host, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	secure.SetDeadline(time.Now().Add(3 * time.Second))
	if secure.Handshake() == nil || calls.Load() != 1 || c.directAddressFailed(cur, q, p) {
		t.Fatal("response or certificate failure triggered replay", calls.Load())
	}
}
