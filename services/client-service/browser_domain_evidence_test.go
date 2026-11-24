package clientservice

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestNativeDNSRoutingHintsScopedTTLAndAmbiguousProtected(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("87.240.137.208")
	var index browserDomainIndex
	index.replace("network-A", []wp.DNSCacheEntry{{Name: "vk.ru", Address: ip.String(), TTL: 10}}, nil, now)
	e := index.evidence("network-A", ip, "cloudflare-ech.com", now)
	if e.Domain != "vk.ru" || e.Restricted || e.Source != "SYSTEM_DNS_CACHE_TTL_HINT" {
		t.Fatal(e)
	}
	for _, tt := range []struct {
		network string
		at      time.Time
	}{{"network-B", now}, {"", now}, {"network-A", now.Add(11 * time.Second)}} {
		e = index.evidence(tt.network, ip, "", tt.at)
		if e.Domain != "" || len(e.Candidates) != 0 {
			t.Fatal("stale/cross-network hint", e)
		}
	}
	index.replace("network-A", []wp.DNSCacheEntry{{Name: "vk.ru", Address: ip.String(), TTL: 10}, {Name: "chatgpt.com", Address: ip.String(), TTL: 10}}, nil, now)
	e = index.evidence("network-A", ip, "", now)
	if !e.Restricted || !e.Ambiguous || e.Domain != "" {
		t.Fatal("protected shared IP falsely authorized DIRECT", e)
	}
	index.replace("network-A", nil, errors.New("unavailable"), now)
	if e = index.evidence("network-A", ip, "", now); e.Restricted || e.Domain != "" {
		t.Fatal("failed snapshot retains hints", e)
	}
}
func TestNativeOpaqueOwnerDefaultAndProtectedEvidence(t *testing.T) {
	c, _, _ := nativeEdgeFixture(t)
	p := profiles.Profile{ID: "chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto, BrowserTransport: "native"}
	tuple := policyTuple("tcp", 443)
	for _, outer := range []string{"", "www.google.com", "cloudflare-ech.com", "web.telegram.org", "claude.ai", "chatgpt.com", "www.youtube.com"} {
		e := c.browser.domains.evidence("net", tuple.Destination.Addr(), outer, time.Now())
		plan := c.nativeOpaquePlan(p, tuple, "net", e)
		if restrictiveBrowserDomain(outer) {
			if plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
				t.Fatal(outer, plan)
			}
		} else if plan.Policy.Action != flowpolicy.Direct {
			t.Fatal("ordinary opaque forced through VPS", outer, plan)
		}
	}
	e := browserDomainEvidence{}
	c.browser.domains.failedDirect("net", p.ID, tuple.Destination, time.Now())
	if plan := c.nativeOpaquePlan(p, tuple, "net", e); plan.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal(plan)
	}
	p.ID = "other"
	if plan := c.nativeOpaquePlan(p, tuple, "net", e); plan.Policy.Action != flowpolicy.Direct {
		t.Fatal("cross-profile failure cache", plan)
	}
	p.ID = "chrome"
	if plan := c.nativeOpaquePlan(p, tuple, "other-net", e); plan.Policy.Action != flowpolicy.Direct {
		t.Fatal("cross-network failure cache", plan)
	}
	p.Rules = []flowpolicy.Rule{{ID: "explicit-block", CIDRs: []string{tuple.Destination.Addr().String() + "/32"}, Action: flowpolicy.Block}}
	if plan := c.nativeOpaquePlan(p, tuple, "net", e); plan.Policy.Action != flowpolicy.Block {
		t.Fatal("rule weakened", plan)
	}
}
func TestNativeDNSFailureMemoryBoundedAndExpires(t *testing.T) {
	var index browserDomainIndex
	now := time.Now()
	dst := netip.MustParseAddrPort("8.8.8.8:443")
	index.failedDirect("n", "p", dst, now)
	if !index.directFailed("n", "p", dst, now) || index.directFailed("n", "p", dst, now.Add(3*time.Minute)) {
		t.Fatal("bad failure TTL")
	}
	index.failedDirect("", "p", dst, now)
	if index.directFailed("", "p", dst, now) {
		t.Fatal("unscoped failure")
	}
	for i := 0; i < 1000; i++ {
		index.failedDirect("n", "p", netip.AddrPortFrom(dst.Addr(), uint16(i+1024)), now)
	}
	if len(index.failed) > 256 {
		t.Fatal("unbounded cache", len(index.failed))
	}
}

func TestProtectedOpaqueAssociationCannotBeDowngradedByDirectIPRule(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	tuple := policyTuple("tcp", 443)
	p.Rules = []flowpolicy.Rule{{ID: "ip-direct", CIDRs: []string{tuple.Destination.Addr().String() + "/32"}, Action: flowpolicy.Direct}}
	for _, e := range []browserDomainEvidence{{Domain: "chatgpt.com", Restricted: true}, {Restricted: true, Ambiguous: true}} {
		plan := c.nativeOpaquePlan(p, tuple, "network", e)
		if plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
			t.Fatal("protected hint weakened by DIRECT rule", plan)
		}
	}
	p.Rules[0].Action = flowpolicy.Block
	if plan := c.nativeOpaquePlan(p, tuple, "network", browserDomainEvidence{Restricted: true}); plan.Policy.Action != flowpolicy.Block {
		t.Fatal("BLOCK weakened", plan)
	}
}

func TestProtectedOuterRestoresRecoveryWithSeveralDNSAliasesOnOneIP(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("149.154.167.40")
	var index browserDomainIndex
	index.replace("net", []wp.DNSCacheEntry{{Name: "web.telegram.org", Address: ip.String(), TTL: 30}, {Name: "kws2.web.telegram.org", Address: ip.String(), TTL: 30}}, nil, now)
	e := index.evidence("net", ip, "web.telegram.org", now)
	if !e.Ambiguous || !e.Restricted || e.Domain != "web.telegram.org" || e.Source != "ECH_PROTECTED_OUTER_HINT" {
		t.Fatal("outer-specific recovery lost to shared DNS aliases", e)
	}
	e = index.evidence("net", ip, "cloudflare-ech.com", now)
	if e.Domain != "" || !e.Restricted {
		t.Fatal("ambiguous IP guessed inner domain", e)
	}
}
