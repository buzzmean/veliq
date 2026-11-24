package clientservice

import (
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
	"net/netip"
	"testing"
)

func TestNativeBrowserSecureDNSRelayAndOrdinaryDirect(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	c.enabled = true
	c.settings.Automatic = true
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	c.Profiles.Upsert(p)
	id := wp.ProcessIdentity{PID: 77, CreationTime: 1, Path: p.Executables[0]}
	tuple := policyTuple("tcp", 443)
	tuple.Destination = netip.MustParseAddrPort("8.8.8.8:443")
	d := wp.ResolveDeferredDecision(c.Classify(id, tuple), "cloudflare-ech.com", "ECH_OUTER_SNI_ONLY")
	if d.Policy.Action != flowpolicy.RelayRequired || d.Route.RelayID != "VPS-01" || !d.BlockOnFailure || d.Policy.Source != "browser_secure_dns_relay" {
		t.Fatal(d)
	}
	p.Rules = []flowpolicy.Rule{{ID: "direct", CIDRs: []string{"8.8.8.8/32"}, Action: flowpolicy.Direct}}
	plan := c.nativeOpaquePlan(p, tuple, "net", browserDomainEvidence{})
	if plan.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal("DoH DIRECT rule weakened relay-only", plan)
	}
	p.Rules[0].Action = flowpolicy.Block
	if plan = c.nativeOpaquePlan(p, tuple, "net", browserDomainEvidence{}); plan.Policy.Action != flowpolicy.Block {
		t.Fatal("explicit BLOCK ignored", plan)
	}
	tuple.Destination = netip.MustParseAddrPort("87.240.137.208:443")
	p.Rules = nil
	if plan = c.nativeOpaquePlan(p, tuple, "net", browserDomainEvidence{}); plan.Policy.Action != flowpolicy.Direct {
		t.Fatal("VK relayed", plan)
	}
	c.enabled = false
	tuple.Destination = netip.MustParseAddrPort("8.8.8.8:443")
	if d = c.Classify(id, tuple); !d.Route.Direct() || d.OpenDeferred != nil {
		t.Fatal("disabled browser DoH still owned", d)
	}
}
