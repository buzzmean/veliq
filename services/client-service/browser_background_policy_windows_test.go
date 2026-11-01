//go:build windows

package clientservice

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

var backgroundPolicyChanges = []string{"unchanged", "unrelated-profile", "optimize-off", "automatic-off", "profile-direct", "profile-rule", "network", "vpn"}

func backgroundPolicyFixture(t *testing.T, owner wp.ProcessIdentity) (*Controller, profilesResult, browserproxy.Request, browserproxy.Plan) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled, c.settings.Automatic = true, true
	p := profiles.Profile{ID: "background-owner", Name: "Background policy fixture", Executables: []string{owner.Path}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "background-net", ObservedAt: time.Now(), ConflictsObservedAt: time.Now()})
	q := browserproxy.Request{Owner: browserproxy.Owner{PID: owner.PID, Birth: owner.CreationTime, Exe: owner.Path, Profile: p.ID}, Source: netip.MustParseAddrPort("127.0.0.1:50103"), Host: "rr1---sn-background.googlevideo.com", Port: 443, Secure: true}
	cur, err := c.browserProfile(q.Owner)
	if err != nil || !cur.enabled {
		t.Fatal("live owner/profile", err)
	}
	plan := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: netip.MustParseAddrPort("74.125.111.131:443"), Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: youtubeLadderSource}}
	return c, cur, q, plan
}

func changeBackgroundPolicy(t *testing.T, c *Controller, p profiles.Profile, change string) bool {
	t.Helper()
	switch change {
	case "unchanged":
		return false
	case "unrelated-profile":
		p.ID, p.Name, p.Executables = "unrelated", "Unrelated application", []string{`C:\Fixture\discord.exe`}
	case "optimize-off":
		c.mu.Lock()
		c.enabled = false
		c.mu.Unlock()
	case "automatic-off":
		c.mu.Lock()
		c.settings.Automatic = false
		c.mu.Unlock()
	case "profile-direct":
		p.Mode = profiles.Direct
	case "profile-rule":
		p.Rules = []flowpolicy.Rule{{ID: "block-public-check", Domains: []string{"www.youtube.com"}, Action: flowpolicy.Block}}
	case "network", "vpn":
		n := *c.network.Load()
		if change == "network" {
			n.Fingerprint = "replacement-net"
		} else {
			n.VPN = []string{"fixture-vpn"}
		}
		c.network.Store(&n)
	default:
		t.Fatal("unknown mutation", change)
	}
	if change == "profile-direct" || change == "profile-rule" || change == "unrelated-profile" {
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
	}
	return change != "unrelated-profile"
}

func backgroundBarrier(t *testing.T) (chan struct{}, func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	t.Cleanup(resume)
	return release, resume
}

func awaitBackground(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("background fixture did not reach its synchronization point")
	}
}

func finishBackground(t *testing.T, c *Controller) {
	t.Helper()
	done := make(chan struct{})
	go func() { c.browser.youtube.workers.Wait(); close(done) }()
	awaitBackground(t, done)
	if c.browser.youtube.snapshot().Selection.BackgroundActive || len(c.browser.probes) != 0 {
		t.Fatal("background worker leaked admission capacity")
	}
}

// A loopback socket records whether an upstream open actually happened. The
// relay here is a counting seam; the cold-flow fixture separately proves mTLS.
type backgroundPolicyRelay struct{ opens atomic.Int32 }

func (r *backgroundPolicyRelay) OpenTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().IsLoopback() {
		return nil, errors.New("fixture refuses non-loopback destination")
	}
	r.opens.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp4", dst.String())
}
func (*backgroundPolicyRelay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, errors.New("fixture has no datagrams")
}

func TestWindowsYouTubeBackgroundPolicyChangeBeforeDNSOpen(t *testing.T) {
	owner := cdnColdOwner(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	destination := listener.Addr().(*net.TCPAddr).AddrPort()
	for _, change := range backgroundPolicyChanges {
		t.Run(change, func(t *testing.T) {
			c, cur, q, p := backgroundPolicyFixture(t, owner)
			relay := &backgroundPolicyRelay{}
			c.Engine.SetRelay("VPS-01", relay)
			entered := make(chan struct{})
			release, resume := backgroundBarrier(t)
			defer resume()
			opened := false
			c.BrowserAlternativeDNS = func(ctx context.Context, _ string, open browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return browserproxy.DNSAnswer{}, ctx.Err()
				}
				conn, err := open(ctx, destination)
				if err == nil {
					opened = true
					conn.Close()
				}
				// Stop before the public origin; this fixture tests the DoH open.
				return browserproxy.DNSAnswer{}, errors.New("fixture DNS stops after observed open")
			}
			key := youtubeScope(cur, q)
			c.youtubeBackgroundRecheck(cur, q, p, key)
			awaitBackground(t, entered)
			cancelled := changeBackgroundPolicy(t, c, cur.profile, change)
			resume()
			finishBackground(t, c)
			r := c.browser.youtube
			if cancelled {
				if opened || relay.opens.Load() != 0 || r.selection.BackgroundFailures != 0 || !r.cache[key].Retry.IsZero() {
					t.Fatalf("stale background attempted upstream or penalized cancellation: opened=%v relay=%d failures=%d cache=%+v", opened, relay.opens.Load(), r.selection.BackgroundFailures, r.cache[key])
				}
			} else if !opened || relay.opens.Load() != 1 || r.selection.BackgroundFailures != 1 {
				t.Fatalf("current background must still attempt authenticated DNS route: opened=%v relay=%d failures=%d", opened, relay.opens.Load(), r.selection.BackgroundFailures)
			}
			if change == "optimize-off" || change == "automatic-off" {
				// OFF compatibility belongs to actual cached-PAC requests, not probes.
				q.Ingress = "PAC_CONNECT"
				p.Destination = destination
				conn, err := c.browserOpen(context.Background(), q, p)
				if err != nil {
					t.Fatal("foreground cached PAC lost OFF compatibility", err)
				}
				conn.Close()
			}
		})
	}
}

func TestWindowsYouTubeBackgroundPolicyChangeBeforeProof(t *testing.T) {
	owner := cdnColdOwner(t)
	for _, change := range backgroundPolicyChanges {
		t.Run(change, func(t *testing.T) {
			c, cur, q, p := backgroundPolicyFixture(t, owner)
			entered := make(chan struct{})
			release, resume := backgroundBarrier(t)
			defer resume()
			server, roots := youtubeTLSHTTPFixture(t, "www.youtube.com", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				close(entered)
				select {
				case <-release:
				case <-request.Context().Done():
					return
				}
				http.Error(w, "fixture public response", http.StatusForbidden)
			}))
			c.BrowserProbeRoots = roots
			c.Backend = &cdnColdBackend{owner: owner, publicAddress: server.Listener.Addr().String(), committed: map[cdnColdTuple]bool{}}
			c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
				return browserproxy.DNSAnswer{Addresses: []netip.Addr{p.Destination.Addr()}, TTL: time.Minute, ObtainedAt: time.Now(), Source: "ISOLATED_FIXTURE"}, nil
			}
			key := youtubeScope(cur, q)
			c.youtubeBackgroundRecheck(cur, q, p, key)
			awaitBackground(t, entered)
			cancelled := changeBackgroundPolicy(t, c, cur.profile, change)
			resume()
			finishBackground(t, c)
			r := c.browser.youtube
			if cancelled {
				if len(r.qualifications) != 0 || len(r.probeEvidence) != 0 || r.selection.BackgroundFailures != 0 || !r.cache[key].Retry.IsZero() {
					t.Fatalf("stale reply changed learning: proofs=%d evidence=%d failures=%d cache=%+v", len(r.qualifications), len(r.probeEvidence), r.selection.BackgroundFailures, r.cache[key])
				}
			} else if len(r.qualifications) != 1 || r.selection.BackgroundFailures != 1 || r.cache[key].Qualified == "" {
				t.Fatalf("current public 403 lost guarded qualification: proofs=%d failures=%d cache=%+v", len(r.qualifications), r.selection.BackgroundFailures, r.cache[key])
			}
		})
	}
}

func TestWindowsYouTubeBackgroundPolicyChangePreservesMediaFailure(t *testing.T) {
	c, cur, q, p := backgroundPolicyFixture(t, cdnColdOwner(t))
	entered := make(chan struct{})
	release, resume := backgroundBarrier(t)
	defer resume()
	c.BrowserAlternativeDNS = func(ctx context.Context, _ string, _ browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return browserproxy.DNSAnswer{}, errors.New("fixture DNS cancelled")
	}
	r := c.browser.youtube
	key := youtubeScope(cur, q)
	c.youtubeBackgroundRecheck(cur, q, p, key)
	awaitBackground(t, entered)
	// Admit a concurrent foreground trial through the normal qualification and
	// slot APIs. Only its transform witness and media failure are injected.
	strategy := r.order[0]
	public := q
	public.Host = "www.youtube.com"
	c.recordLocalProbe(public, p, strategy, browserproxy.ProbeResult{Status: http.StatusForbidden}, true)
	r.completeCDNQualification(key, strategy, time.Now())
	endpoint := cdnEndpoint{q.Host, p.Destination.String()}
	sibling := testSibling(true)
	sibling.MediaRequired, sibling.MediaBytes = true, cdnStrongBytes+1
	chosen, token, ok := r.takeEndpointTrial(key, time.Now(), sibling, endpoint)
	if !ok || chosen != strategy {
		t.Fatal("fixture did not admit the foreground media trial")
	}
	changeBackgroundPolicy(t, c, cur.profile, "optimize-off")
	// An existing pinned media flow can report failure after OFF. Its meter
	// callback must retain the real cooldown when the background worker exits.
	meter := &youtubeMeter{r: r, key: key, stage: "LOCAL", strategy: strategy, trial: true, trialID: token, host: q.Host, destination: p.Destination.String()}
	meter.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	r.mu.Lock()
	before := r.cache[key]
	endpointKey := cdnEndpointKey{key, endpoint, strategy}
	beforeEndpoint := r.endpointNegative[endpointKey]
	r.mu.Unlock()
	if r.selection.TrialFailures != 1 || r.trialActive || before.Retry.IsZero() || before.TrialAfter.IsZero() || beforeEndpoint.Until.IsZero() {
		t.Fatal("fixture did not record a real media failure")
	}
	resume()
	finishBackground(t, c)
	after := r.cache[key]
	if after.Failures != before.Failures || after.Tried != before.Tried || after.Reason != before.Reason || !after.Retry.Equal(before.Retry) || !after.TrialAfter.Equal(before.TrialAfter) || !r.endpointNegative[endpointKey].Until.Equal(beforeEndpoint.Until) || r.selection.BackgroundFailures != 0 {
		t.Fatalf("background cancellation changed the media failure: before=%+v after=%+v", before, after)
	}
}
