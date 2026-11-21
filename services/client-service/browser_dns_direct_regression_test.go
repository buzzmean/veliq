package clientservice

import (
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestBrowserDNSAndGoogleRecoveryDoNotRelayHealthyOrdinarySitesOrGames(t *testing.T) {
	c, _, _ := nativeEdgeFixture(t)
	c.enabled = true
	c.settings.Automatic = true
	now := time.Now()
	for _, exe := range []string{`C:\Apps\chrome.exe`, `C:\Apps\msedge.exe`} {
		p := profiles.Profile{ID: exe, Executables: []string{exe}, Mode: profiles.Auto, BrowserTransport: "native"}
		c.Profiles.Upsert(p)
		for _, ip := range []string{"64.233.162.95:443", "142.251.1.94:443"} {
			c.browser.domains.googleFailed("network", p.ID, netip.MustParseAddrPort(ip), "DIRECT_TLS_FIRST_REPLY_TIMEOUT", now)
		}
		for _, tc := range []struct {
			host, ip string
			want     flowpolicy.Action
		}{
			{"vk.ru", "87.240.137.208", flowpolicy.Direct},
			{"yandex.ru", "77.88.55.88", flowpolicy.Direct},
			{"r1.googlevideo.com", "173.194.180.1", flowpolicy.RelayRequired},
			{"chatgpt.com", "104.18.32.7", flowpolicy.RelayRequired},
			{"web.telegram.org", "149.154.167.99", flowpolicy.RelayRequired},
		} {
			dst := netip.AddrPortFrom(netip.MustParseAddr(tc.ip), 443)
			c.browser.domains.observeBrowserDNS("network", p.ID, []browserproxy.DNSHint{{Name: tc.host, Address: dst.Addr().String(), TTL: 60}}, now)
			evidence := c.browser.domains.profileEvidence("network", p.ID, dst.Addr(), "", now)
			tuple := policyTuple("tcp", 443)
			tuple.Destination = dst
			plan := c.nativeOpaquePlan(p, tuple, "network", evidence)
			if evidence.Domain != tc.host || plan.Policy.Action != tc.want || plan.Destination != dst {
				t.Fatal(exe, tc, evidence, plan)
			}
			if tc.want == flowpolicy.RelayRequired && plan.Policy.Fallback != flowpolicy.Required {
				t.Fatal("protected DNS failed open", plan)
			}
		}
		// No hints: ordinary ECH retains the owner's DIRECT default even after Google failures.
		for _, ip := range []string{"87.240.137.209:443", "77.88.55.89:443"} {
			tuple := policyTuple("tcp", 443)
			tuple.Destination = netip.MustParseAddrPort(ip)
			if plan := c.nativeOpaquePlan(p, tuple, "network", browserDomainEvidence{}); plan.Policy.Action != flowpolicy.Direct {
				t.Fatal("global opaque relay regression", plan)
			}
		}
		c.enabled = false
		for _, proto := range []string{"tcp", "udp"} {
			d := c.Classify(wp.ProcessIdentity{PID: 77, CreationTime: 1, Path: exe}, policyTuple(proto, 53))
			if !d.Route.Direct() || d.Deferred || d.OpenDeferred != nil || d.DNSExchange != nil {
				t.Fatal("off DNS still captured", d)
			}
		}
		c.enabled = true
	}
	// Unprofiled games do not inherit browser DNS/DoH or learned Google policy.
	id := wp.ProcessIdentity{PID: 88, CreationTime: 1, Path: `C:\Games\OtherGame.exe`}
	for _, port := range []uint16{53, 443, 27025} {
		d := c.Classify(id, policyTuple("udp", port))
		if !d.Route.Direct() || d.DNSExchange != nil || d.Deferred {
			t.Fatal("browser policy affected game", d)
		}
	}
}

func TestBrowserFailureCallbacksCannotLearnAfterDisableOrNetworkChange(t *testing.T) {
	for _, off := range []bool{false, true} {
		c, cur := timeoutFixture(t)
		c.enabled = !off
		c.settings.Automatic = true
		if !off {
			c.network.Store(&wp.NetworkContext{Fingerprint: "changed-network"})
		}
		p := browserproxy.Plan{Destination: netip.MustParseAddrPort("64.233.162.95:443"), Policy: flowpolicy.Result{Action: flowpolicy.Direct}}
		if c.recordNativeBrowserFailure(cur, browserproxy.Request{Port: 443}, p, true, "DIRECT_TLS_FIRST_REPLY_TIMEOUT") {
			t.Fatal("stale callback accepted")
		}
		if c.browser.domains.directFailed(cur.network, cur.profile.ID, p.Destination, time.Now()) || len(c.browser.domains.google) != 0 {
			t.Fatal("stop/old network poisoned cache")
		}
	}
}
func TestBrowserDNSDiagnosticsAreBoundedAndExcludeExpiredHints(t *testing.T) {
	var x browserDomainIndex
	now := time.Now()
	for i := 0; i < 32; i++ {
		x.observeBrowserDNS("network", "chrome", []browserproxy.DNSHint{{Name: "vk.ru", Address: netip.AddrFrom4([4]byte{87, 240, 137, byte(i + 1)}).String(), TTL: 60}}, now)
	}
	x.observeBrowserDNS("network", "chrome", []browserproxy.DNSHint{{Name: "expired.example", Address: "77.88.55.88", TTL: 1}}, now.Add(-2*time.Second))
	s := x.snapshot()
	if s["browser_scoped_addresses"] != 32 || len(s["browser_scoped_hints"].([]map[string]any)) != 16 || s["browser_scoped_hints_omitted"] != 16 {
		t.Fatal(s)
	}
}
