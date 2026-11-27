//go:build windows

package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	"github.com/buzzmean/veliq/core/routing"
	wp "github.com/buzzmean/veliq/platform/windows"
)

type authorityAdmissionSpy struct {
	calls int
	flow  routing.Flow
}

func (s *authorityAdmissionSpy) Enabled() bool { return false }
func (s *authorityAdmissionSpy) ManagesFlow(f routing.Flow) bool {
	s.calls++
	s.flow = f
	return true
}
func (*authorityAdmissionSpy) OpenTCP(context.Context, routing.Flow) (net.Conn, string, error) {
	return nil, "", errors.New("disabled fleet must not open")
}
func (*authorityAdmissionSpy) OpenDatagram(context.Context, routing.Flow) (routing.Datagram, string, error) {
	return nil, "", errors.New("disabled fleet must not open")
}

// No owner proxy, registry, service or capture settings are changed. A real
// Windows identity and loopback-only DNS fixture exercise the whole policy path.
func TestWindowsUnregisteredOwnerAuthorityHonorsProtectedRelay(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	id, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	c.BrowserOwnerSID, err = wp.ProcessUserSID(id)
	if err != nil {
		t.Fatal(err)
	}
	c.enabled, c.selfExecutable = true, "isolated-service-owner.exe"
	c.BrowserResolver = continuityResolver(t, [4]byte{192, 0, 2, 88})
	provider := &unwantedGameRelay{}
	c.Engine.SetRelay("VPS-01", provider)
	admission := &authorityAdmissionSpy{}
	c.Engine.SetFleetRelay(admission)
	q := browserproxy.Request{Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: "owner-system-passthrough"}, Source: netip.MustParseAddrPort("127.0.0.1:55123"), Host: "chatgpt.com", Port: 443, Secure: true}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	plan, err := c.authorityPlan(ctx, q)
	if err != nil || plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
		t.Fatal("protected authority did not resolve to a required relay", plan.Policy, err)
	}
	conn, err := c.authorityOpen(ctx, q, plan)
	if conn != nil {
		conn.Close()
		t.Fatal("failed required provider escaped to another route")
	}
	if err == nil || provider.calls.Load() != 1 {
		t.Fatal("unregistered owner bypassed its resolved relay policy", provider.calls.Load(), err)
	}
	discovered, ok := discoveredApplication(id)
	if !ok || admission.calls != 1 || admission.flow.ApplicationID != discovered.ID || admission.flow.PinnedPolicy == nil || !admission.flow.PinnedPolicy.ImplicitRelay {
		t.Fatal("ephemeral AUTO lost implicit admission provenance", admission.calls, admission.flow.ApplicationID)
	}
	// An ordinary tunnel cannot gain browser recovery when a new stored profile
	// later borrows the passthrough label. Current authentication alone is not
	// enough: the original role snapshot is required as well.
	q.Host = "ordinary.example.org"
	ordinary, err := c.authorityPlan(ctx, q)
	if err != nil || ordinary.BrowserRecoveryAuthorized || ordinary.Policy.Action != flowpolicy.Direct {
		t.Fatal("unregistered ordinary plan gained browser recovery", ordinary, err)
	}
	if err := c.Profiles.Upsert(profiles.Profile{ID: q.Owner.Profile, Name: "New browser", Executables: []string{id.Path, "chrome.exe"}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}); err != nil {
		t.Fatal(err)
	}
	if !c.authorityBrowser(q) || c.authorityWatchDirect(q, ordinary) {
		t.Fatal("new browser profile attached recovery to an ordinary old plan")
	}
	allowed := ordinary
	allowed.BrowserRecoveryAuthorized = true
	if !c.authorityWatchDirect(q, allowed) {
		t.Fatal("current authenticated browser role was rejected")
	}
	q.Owner.Birth++
	if c.authorityWatchDirect(q, allowed) {
		t.Fatal("stale identity received browser recovery")
	}
	if _, err := c.authorityOpen(ctx, q, plan); err == nil || provider.calls.Load() != 1 {
		t.Fatal("stale identity reached routing")
	}
}
