package clientservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

func TestOrdinaryKnownHostDirectBeforeRelayAndOpaqueCapacityFallback(t *testing.T) {
	c, cur := timeoutFixture(t)
	cur.profile = profiles.Profile{ID: "chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto, BrowserTransport: "native"}
	for _, host := range []string{"chromewebstore.google.com", "www.google.com", "vk.ru", "ordinary-test.net", ""} {
		calls := 0
		p := browserproxy.Plan{DirectCandidates: []netip.AddrPort{netip.MustParseAddrPort("74.125.111.131:443"), netip.MustParseAddrPort("87.240.137.208:443")}, Enabled: true, Network: cur.network, Destination: netip.MustParseAddrPort("74.125.111.131:443"), OrdinaryCapacityDirect: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required, Source: "browser_opaque_google_failure_cache"}}
		a, b := net.Pipe()
		conn, actual, err := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: host, Port: 443, Secure: true}, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
			calls++
			if plan.Policy.Action == flowpolicy.RelayRequired {
				return nil, errOpaqueGoogleCapacity
			}
			return a, nil
		})
		wantCalls, wantSource := 1, "ordinary_direct_first"
		if host == "" {
			wantCalls = 2
			wantSource = "browser_ordinary_capacity_direct"
		}
		if err != nil || calls != wantCalls || actual.Policy.Action != flowpolicy.Direct || actual.Policy.Source != wantSource {
			t.Fatal(host, err, calls, actual)
		}
		if host == "" && conn != a {
			t.Fatal("opaque fallback lost actual DIRECT connection")
		}
		conn.Close()
		b.Close()
	}
	if c.relayUsage().snapshot().CapacityDirectFallbacks != 1 {
		t.Fatal("missing fallback evidence")
	}
}
func TestRelayCapacityNeverDowngradesProtectedOrExplicitPolicy(t *testing.T) {
	c, cur := timeoutFixture(t)
	cur.profile = profiles.Profile{ID: "chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto, BrowserTransport: "native"}
	for _, host := range []string{"r1.googlevideo.com", "www.youtube.com", "i.ytimg.com", "yt3.ggpht.com", "youtubei.googleapis.com", "chatgpt.com", "web.telegram.org", "claude.ai", "dns.google", ""} {
		p := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: netip.MustParseAddrPort("74.125.111.131:443"), Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}
		calls := 0
		_, actual, err := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: host, Port: 443, Secure: true}, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
			calls++
			return nil, errVideoRelayCapacity
		})
		if err == nil || calls != 1 || actual.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal("DIRECT leak", host, calls, actual, err)
		}
	}
	for _, failure := range []error{io.ErrUnexpectedEOF, errors.New("relay unreachable"), context.Canceled} {
		p := browserproxy.Plan{Enabled: true, Destination: netip.MustParseAddrPort("74.125.111.131:443"), Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required, Source: "auto"}}
		calls := 0
		_, _, _ = c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: "www.google.com", Port: 443}, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
			calls++
			return nil, failure
		})
		if calls != 1 {
			t.Fatal("non-capacity error hidden", failure, calls)
		}
	}
	cur.profile.Rules = []flowpolicy.Rule{{ID: "required", Domains: []string{"chromewebstore.google.com"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}
	p := browserproxy.Plan{Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	_, actual, err := c.capacityDirectFallback(context.Background(), cur, browserproxy.Request{Host: "chromewebstore.google.com", Port: 443}, p, nil, errOpaqueGoogleCapacity, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		t.Fatal("explicit required downgraded")
		return nil, nil
	})
	if err == nil || actual.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal(actual, err)
	}
	if nativeFailureCode(errVideoRelayCapacity) != "GOOGLEVIDEO_RELAY_ADMISSION_CAPACITY" || nativeFailureCode(errOpaqueGoogleCapacity) != "OPAQUE_GOOGLE_RELAY_ADMISSION_CAPACITY" {
		t.Fatal("local capacity mislabeled as transport open_io_failed")
	}
}
