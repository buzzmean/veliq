package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
)

func TestOpaqueDirectFailureNeverPoisonsOtherUnknownDestinations(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Port: 443, Secure: true}
	p := boundedDirectPlan()
	p.Enabled = true
	calls := 0
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		calls++
		if calls == 1 {
			if plan.Policy.Action != flowpolicy.Direct {
				t.Fatal(plan)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > browserDirectAttempt {
				t.Fatal("unbounded DIRECT")
			}
			return nil, context.DeadlineExceeded
		}
		if plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
			t.Fatal("unsafe fallback", plan)
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	conn, plan, err := c.openOpaqueBrowserPlan(context.Background(), cur, q, p, open)
	if err != nil || calls != 2 || plan.Policy.Source != "opaque_direct_open_retry" {
		t.Fatal(plan, err, calls)
	}
	conn.Close()
	c.recordNativeBrowserStall(cur, q, p, true)
	c.observeDirectOpen(cur, q, p, context.DeadlineExceeded, time.Now())
	if s := c.browser.directTimeouts.Stats(); s.ActiveOrigins != 0 || s.ActiveAddresses != 0 || s.Stalls != 0 {
		t.Fatal("empty domain learned", s)
	}
	if !c.browser.domains.directFailed(cur.network, cur.profile.ID, p.Destination, time.Now()) {
		t.Fatal("IP failure not learned")
	}
	other := netip.MustParseAddrPort("1.1.1.1:443")
	if c.browser.domains.directFailed(cur.network, cur.profile.ID, other, time.Now()) {
		t.Fatal("unrelated IP poisoned")
	}
	if _, ok := c.steerTimedOutOrigin(p, cur, q, time.Now()); ok {
		t.Fatal("empty-domain cache steered all browser traffic")
	}
}
func TestOpaqueOwnerFailureDoesNotAuthorizeRelayOrPoisonIP(t *testing.T) {
	c, cur := timeoutFixture(t)
	p := boundedDirectPlan()
	p.Enabled = true
	calls := 0
	ownerErr := errors.New("NATIVE_OWNER_SID_MISMATCH")
	_, _, err := c.openOpaqueBrowserPlan(context.Background(), cur, browserproxy.Request{Port: 443}, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		calls++
		return nil, ownerErr
	})
	if !errors.Is(err, ownerErr) || calls != 1 || c.browser.domains.directFailed(cur.network, cur.profile.ID, p.Destination, time.Now()) {
		t.Fatal("owner failure retried/poisoned", err, calls)
	}
}
