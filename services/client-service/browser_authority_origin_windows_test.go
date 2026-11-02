//go:build windows

package clientservice

import (
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/internal/browserfixture"
	"testing"
)

func verifyAuthorityManualFallback(t *testing.T, c *Controller, f *browserfixture.OriginReuse, tcp, rx uint64) {
	t.Helper()
	if f.Bootstrap(t).Source != "127.0.0.1" {
		t.Fatal("pre-activation DIRECT bootstrap missing")
	}
	for _, r := range f.Requests(t) {
		t.Logf("ORIGIN_MANUAL_FALLBACK_REQUEST %+v", r)
		if r.Source != "127.0.0.2" || r.Protocol != 2 || r.BodyBytes == 0 {
			t.Error("PAC resolver failure escaped authenticated relay")
		}
	}
	server := c.browser.authority.fallback
	if server == nil {
		t.Fatal("fallback listener missing")
	}
	seen := map[string]bool{}
	for _, r := range server.Snapshot().Records {
		if r.Sent == 0 || r.Received == 0 {
			continue
		}
		if r.Owner.Profile != "origin-reuse" || r.Owner.PID == 0 || r.Owner.Birth == 0 || r.Plan.Policy.Action != flowpolicy.RelayRequired || r.Plan.Policy.Fallback != flowpolicy.Required {
			t.Error("fallback authority owner/route/floor mismatch")
		}
		seen[r.Domain] = true
	}
	if !seen[browserfixture.ReuseLocalHost] || !seen[browserfixture.ReuseRequiredHost] || tcp == 0 || rx == 0 {
		t.Error("fallback ingress and authenticated relay bytes missing")
	}
	if c.authorityStatus().ChromeRequests != 0 {
		t.Error("manual fallback falsely claimed primary PAC uptake")
	}
	t.Logf("ORIGIN_MANUAL_FALLBACK_PROOF primary_uptake=false protected_direct=0 relay_tcp=%d relay_rx=%d", tcp, rx)
}
