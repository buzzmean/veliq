package clientservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

func TestKnownRelayOriginRecoveryUsesIndependentDNSAndWarmNegativeCache(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "web.telegram.org", Port: 443, Secure: true}
	p := boundedDirectPlan()
	p.Policy = browserDNSPolicy(cur)
	p.Enabled = true
	one := p.Destination
	two := netip.MustParseAddrPort("8.8.4.4:443")
	var lookups, badOpens, goodOpens atomic.Int32
	c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		lookups.Add(1)
		return browserproxy.DNSAnswer{Addresses: []netip.Addr{one.Addr(), two.Addr()}, TTL: time.Minute, ObtainedAt: time.Now()}, nil
	}
	serverHello := append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)
	hello := []byte{22, 3, 1, 0, 7, 1, 0, 0, 3, 1, 2, 3}
	open := func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		if p.Policy.Action != flowpolicy.RelayRequired || p.Policy.Fallback != flowpolicy.Required || p.Policy.RelayID != "VPS-01" {
			t.Fatal("DIRECT leak or policy downgrade", p)
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			payload := make([]byte, len(hello))
			if _, err := io.ReadFull(b, payload); err != nil {
				return
			}
			if p.Destination == two {
				b.Write(serverHello)
			}
		}()
		if p.Destination == one {
			badOpens.Add(1)
		} else if p.Destination == two {
			goodOpens.Add(1)
		} else {
			a.Close()
			b.Close()
			return nil, errors.New("unexpected IP")
		}
		return a, nil
	}
	for i := 0; i < 2; i++ {
		conn, plan, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && plan.Destination != two {
			t.Fatal("warm flow reused quarantined DNS IP", plan)
		}
		conn.Write(hello)
		body, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || len(body) != len(serverHello) {
			t.Fatal(err, len(body))
		}
		report := conn.(browserproxy.OriginReporter).OriginAttempts()
		if report.Selected != two.String() {
			t.Fatal(report)
		}
	}
	if lookups.Load() != 1 || badOpens.Load() != 1 || goodOpens.Load() != 2 {
		t.Fatal(lookups.Load(), badOpens.Load(), goodOpens.Load())
	}
}

func TestKnownOriginAlternateCannotBypassIPBlockOrDirectRule(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "ordinarysite.com", Port: 443, Secure: true}
	dst := netip.MustParseAddrPort("8.8.4.4:443")
	for _, action := range []flowpolicy.Action{flowpolicy.Block, flowpolicy.Direct, flowpolicy.DirectPlus} {
		cur.profile.Rules = []flowpolicy.Rule{{ID: "owner-ip-rule", CIDRs: []string{"8.8.4.4/32"}, Action: action}}
		if err := c.validateKnownCandidate(cur, q, dst, "VPS-01"); !errors.Is(err, browserproxy.ErrOriginCandidatePolicy) {
			t.Fatal("IP rule bypassed", action, err)
		}
	}
}
