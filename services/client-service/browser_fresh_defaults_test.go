package clientservice

import (
	"github.com/buzzmean/neexitlag/core/profiles"
	"testing"
)

func TestFreshNativeProfileConfiguresAUTOWithoutPACWhileOptimizationOff(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	if _, err := edgeCall(c, "profile.set", p); err != nil {
		t.Fatal(err)
	}
	if !nativeBrowserProfile(findNativeEdge(c)) || b.ready {
		t.Fatal("metadata configuration armed capture or failed")
	}
	if c.browser.edge != nil && len(c.browser.edge.saved.Owned) > 0 {
		t.Fatal("fresh configuration wrote policy")
	}
}
func TestFreshNativeProfileCannotPublishAgainstUnreadyActiveCapture(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	c.enabled = true
	c.settings.Automatic = true
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	if _, err := edgeCall(c, "profile.set", p); err == nil {
		t.Fatal("active unready backend accepted")
	}
	if findNativeEdge(c).Mode != profiles.Direct {
		t.Fatal("failed preparation replaced profile")
	}
}
