package clientservice

import (
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"testing"
)

func TestFreshNativeDoesNotWaitForPACAndUsesOwnerOpaqueDirectDefault(t *testing.T) {
	for _, edge := range []bool{false, true} {
		c, p, _ := nativeEdgeFixture(t)
		if !edge {
			p.Executables = []string{`C:\Apps\chrome.exe`}
			p.AppPreset = ""
		}
		p.Mode = profiles.Auto
		p.BrowserTransport = "native"
		c.Profiles.Upsert(p)
		c.enabled = true
		c.settings.Automatic = true
		c.browser.readiness.enforced.Store(true)
		id := wp.ProcessIdentity{PID: 77, CreationTime: 1, Path: p.Executables[0]}
		initial := c.Classify(id, policyTuple("tcp", 443))
		if !initial.Deferred || initial.OpenDeferred == nil || !initial.NewConnectionsOnly {
			t.Fatal("native still waits for PAC", initial)
		}
		for _, host := range []string{"chatgpt.com", "claude.ai", "web.telegram.org"} {
			d := wp.ResolveDeferredDecision(initial, host, "TLS_SNI")
			if d.Policy.Action != flowpolicy.RelayRequired || !d.BlockOnFailure || d.Route.RelayID != "VPS-01" {
				t.Fatal(host, d)
			}
		}
		opaque := wp.ResolveDeferredDecision(initial, "cloudflare-ech.com", "ECH_OUTER_SNI_ONLY")
		if opaque.Policy.Action != flowpolicy.Direct || opaque.BlockOnFailure || !opaque.Route.Direct() {
			t.Fatal("unidentified ordinary ECH forced through VPS", opaque)
		}
		ordinary := wp.ResolveDeferredDecision(initial, "ordinary.example", "TLS_SNI")
		if !ordinary.Route.Direct() || ordinary.Block {
			t.Fatal(ordinary)
		}
		quic := c.Classify(id, policyTuple("udp", 443))
		if !quic.Block || !quic.BlockOnFailure || quic.Policy.Source != "browser_native_quic_tcp_fallback" {
			t.Fatal("opaque QUIC leaked", quic)
		}
		dns := c.Classify(id, policyTuple("udp", 53))
		if !dns.Route.Direct() || dns.Deferred {
			t.Fatal(dns)
		}
		c.settings.Automatic = false
		off := c.Classify(id, policyTuple("tcp", 443))
		if !off.Route.Direct() || off.Block || off.Deferred || off.OpenDeferred != nil {
			t.Fatal("automatic off trapped browser", off)
		}
	}
}

func TestNativeBrowserMatchesEveryNetworkServicePIDAfterProfilePublication(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	c.enabled = true
	p.Mode = profiles.Direct
	p.BrowserTransport = ""
	c.Profiles.Upsert(p)
	child := wp.ProcessIdentity{PID: 777, ParentPID: 77, CreationTime: 2, ParentCreationTime: 1, Path: p.Executables[0]}
	if d := c.Classify(child, policyTuple("tcp", 443)); d.OpenDeferred != nil {
		t.Fatal("DIRECT profile captured")
	}
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	p.AppPreset = "edge-sites"
	c.Profiles.Upsert(p)
	// No optimize restart or root-PID pinning. A sandbox NetworkService child has
	// the same executable identity but its own PID and process creation time.
	for _, pid := range []uint32{777, 778, 779} {
		child.PID = pid
		d := c.Classify(child, policyTuple("tcp", 443))
		if !d.Deferred || d.OpenDeferred == nil || d.Flow.ApplicationID != p.ID {
			t.Fatal("utility child missed hot profile", pid, d)
		}
	}
	unknown := child
	unknown.Path = `C:\Other\msedge.exe`
	if d := c.Classify(unknown, policyTuple("tcp", 443)); d.OpenDeferred != nil {
		t.Fatal("path boundary weakened")
	}
	game := wp.ProcessIdentity{PID: 999, CreationTime: 1, Path: `C:\Games\cs2.exe`}
	d := c.Classify(game, policyTuple("udp", 443))
	if d.Block || !d.Route.Direct() {
		t.Fatal("game UDP policy changed", d)
	}
}
