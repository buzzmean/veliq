package clientservice

import (
	"context"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
	"testing"
)

type nativeDisableFixture struct {
	nativeBackendFixture
	changes int
	old     int
}

func (b *nativeDisableFixture) ReconfigureNewConnections(_ string, f func() error) error {
	b.changes++
	return f()
}
func (b *nativeDisableFixture) Reconfigure(_ string, f func() error) error { b.old++; return f() }
func TestNativeOptOutDoesNotResetEstablishedFlows(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	b := &nativeDisableFixture{}
	b.ready = true
	c.Backend = b
	c.enabled = true
	c.settings.Automatic = true
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	c.Profiles.Upsert(p)
	p.Mode = profiles.Direct
	p.BrowserTransport = ""
	p.BrowserAutoDisabled = true
	if _, e := edgeCall(c, "profile.set", p); e != nil {
		t.Fatal(e)
	}
	if b.old != 0 || b.changes != 1 || !findNativeEdge(c).BrowserAutoDisabled {
		t.Fatal("old flows reset or opt-out lost", b.old, b.changes)
	}
}
func TestFreshNativeDisableAndHostStopNeedNoPACListeners(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	c.Profiles.Upsert(p)
	c.settings.Automatic = true
	c.enabled = true
	b.ready = true
	id := wp.ProcessIdentity{PID: 77, CreationTime: 1, Path: p.Executables[0]}
	if _, e := edgeCall(c, "optimize", map[string]bool{"enabled": false}); e != nil {
		t.Fatal(e)
	}
	for _, proto := range []string{"tcp", "udp"} {
		d := c.Classify(id, policyTuple(proto, 443))
		if d.Block || !d.Route.Direct() || d.Deferred || d.OpenDeferred != nil {
			t.Fatal("disabled browser retained interception", d)
		}
	}
	if findNativeEdge(c).Mode != profiles.Auto {
		t.Fatal("OFF destroyed AUTO intent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := c.CloseForHost(ctx); e != nil {
		t.Fatal(e)
	}
	if c.browser.server != nil && c.browser.server.Snapshot().Listening {
		t.Fatal("unneeded listener retained")
	}
	if c.browser.edge != nil && c.browser.edge.server != nil && c.browser.edge.server.Snapshot().Listening {
		t.Fatal("unneeded Edge listener retained")
	}
}

func TestLateNativeEnableCannotRearmAfterExplicitOff(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	if _, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID}); err == nil || err.Error() != "NATIVE_OPTIMIZATION_DISABLED" {
		t.Fatal("late activation accepted", err)
	}
	if b.ready || findNativeEdge(c).Mode != profiles.Direct {
		t.Fatal("late preparation rearmed capture")
	}
}
