package clientservice

import (
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

func TestGoogleSNISelectiveBlockDoesNotRelayHealthyOrdinaryHints(t *testing.T) {
	c, _, _ := nativeEdgeFixture(t)
	p := profiles.Profile{ID: "chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto, BrowserTransport: "native"}
	now := time.Now()
	dst := netip.MustParseAddrPort("74.125.111.131:443")
	c.browser.domains.googleFailed("network", p.ID, dst, "DIRECT_TLS_FIRST_REPLY_TIMEOUT", now)
	c.browser.domains.googleFailed("network", p.ID, netip.MustParseAddrPort("173.194.151.68:443"), "DIRECT_TLS_FIRST_REPLY_TIMEOUT", now)
	c.browser.domains.failedDirect("network", p.ID, dst, now)
	tuple := policyTuple("tcp", 443)
	tuple.Destination = dst
	for _, host := range []string{"www.google.com", "www.gstatic.com", "fonts.googleapis.com", "lh3.googleusercontent.com"} {
		for _, owned := range []bool{false, true} {
			var evidence browserDomainEvidence
			if owned {
				c.browser.domains.observeBrowserDNS("network", p.ID, []browserproxy.DNSHint{{Name: host, Address: dst.Addr().String(), TTL: 60}}, now)
				evidence = c.browser.domains.profileEvidence("network", p.ID, dst.Addr(), "", now)
				// The next independent browser response is scoped to another address below.
				c.browser.domains.mu.Lock()
				delete(c.browser.domains.owned, browserDNSKey{"network", p.ID, dst.Addr()})
				c.browser.domains.mu.Unlock()
			} else {
				evidence = c.browser.domains.profileEvidence("network", p.ID, dst.Addr(), host, now)
			}
			plan := c.nativeOpaquePlan(p, tuple, "network", evidence)
			if evidence.Domain != host || plan.Policy.Action != flowpolicy.Direct || plan.Policy.Source != "browser_ordinary_google_hint_direct" {
				t.Fatal(host, owned, evidence, plan)
			}
		}
	}
	// No ordinary hint is available: the limited existing failure recovery still works.
	if plan := c.nativeOpaquePlan(p, tuple, "network", browserDomainEvidence{}); plan.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal(plan)
	}
	for _, host := range []string{"youtubei.googleapis.com", "yt3.googleusercontent.com", "rr1.googlevideo.com", "i.ytimg.com", "www.youtube.com"} {
		if ordinaryGoogleDomain(host) {
			t.Fatal("protected alias misclassified", host)
		}
		evidence := c.browser.domains.profileEvidence("network", p.ID, dst.Addr(), host, now)
		if plan := c.nativeOpaquePlan(p, tuple, "network", evidence); plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
			t.Fatal(host, plan)
		}
	}
	c.browser.domains.observeBrowserDNS("network", p.ID, []browserproxy.DNSHint{{Name: "chatgpt.com", Address: dst.Addr().String(), TTL: 60}}, now)
	evidence := c.browser.domains.profileEvidence("network", p.ID, dst.Addr(), "www.google.com", now)
	if plan := c.nativeOpaquePlan(p, tuple, "network", evidence); plan.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal("outer hint weakened protected DNS", evidence, plan)
	}
	p.Rules = []flowpolicy.Rule{{ID: "block", CIDRs: []string{dst.Addr().String() + "/32"}, Action: flowpolicy.Block}}
	if plan := c.nativeOpaquePlan(p, tuple, "network", browserDomainEvidence{Domain: "www.google.com"}); plan.Policy.Action != flowpolicy.Block {
		t.Fatal("explicit BLOCK lost", plan)
	}
}

func TestOrdinaryGoogleFailureRequiresSameHintSetAndExpires(t *testing.T) {
	c, _, _ := nativeEdgeFixture(t)
	p := profiles.Profile{ID: "chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto, BrowserTransport: "native"}
	dst := netip.MustParseAddrPort("74.125.111.131:443")
	tuple := policyTuple("tcp", 443)
	tuple.Destination = dst
	evidence := browserDomainEvidence{Ambiguous: true, Candidates: []string{"www.google.com", "fonts.googleapis.com"}}
	now := time.Now()
	c.browser.domains.failedDirect("network", p.ID, dst, now)
	if plan := c.nativeOpaquePlan(p, tuple, "network", evidence); plan.Policy.Action != flowpolicy.Direct {
		t.Fatal("unrelated opaque IP error relayed ordinary hints", plan)
	}
	c.browser.domains.recordOrdinaryGoogleFailure("network", p.ID, dst, evidence, now)
	if plan := c.nativeOpaquePlan(p, tuple, "network", evidence); plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Source != "browser_ordinary_google_failure_cache" {
		t.Fatal(plan)
	}
	for _, e := range []browserDomainEvidence{{Domain: "www.gstatic.com"}, {Domain: "www.google.com"}} {
		if plan := c.nativeOpaquePlan(p, tuple, "network", e); plan.Policy.Action != flowpolicy.Direct {
			t.Fatal("different hint set inherited failure", plan)
		}
	}
	if c.browser.domains.ordinaryGoogleFailed("network", p.ID, dst, evidence, now.Add(3*time.Minute)) || c.browser.domains.ordinaryGoogleFailed("other", p.ID, dst, evidence, now) {
		t.Fatal("TTL/network scope failed")
	}
	evidence.Candidates = append(evidence.Candidates, "www.youtube.com")
	evidence.Restricted = true
	if ordinaryGoogleEvidence(evidence) {
		t.Fatal("protected ambiguity authorized DIRECT")
	}
}
