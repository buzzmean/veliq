package clientservice

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestAutomaticBinary443KeepsHealthyDirectAndOriginalBytes(t *testing.T) {
	for _, failover := range []string{"DIRECT", "BLOCK"} {
		t.Run(failover, func(t *testing.T) {
			c, cur, q, p := automaticFixture(t)
			c.settings.Failover = failover
			cur.automaticRevision = ""
			cur = c.captureAutomaticScope(cur)
			q.Host, q.Secure = "", false
			tuple := destTuple("tcp", p.Destination.Addr().String(), 443)
			payload := []byte{1, 0, 0, 8, 9, 7, 6, 5}
			a, b := net.Pipe()
			go func() { defer b.Close(); _, _ = b.Write(payload) }()
			prefix, domain, why := wp.ReadDeferredHello(a)
			a.Close()
			if why != "NON_TLS_BINARY" || domain != "" || !bytes.Equal(prefix, payload) {
				t.Fatal("positive framing lost", why, domain, prefix)
			}
			decision := wp.ResolveDeferredDecision(c.Classify(cur.id, tuple), domain, why)
			if decision.Block || !decision.AllowNonTLSDirect || !decision.Route.Direct() || decision.Policy.Source != "auto_direct_default" || decision.OpenDeferred == nil {
				t.Fatalf("ordinary binary socket denied: %+v", decision)
			}
			p = c.automaticApplicationPlan(cur, q, tuple, decision, why)
			var opens int
			conn, actual, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
				opens++
				if plan.Policy.Action != flowpolicy.Direct || plan.FirstFlightManaged {
					t.Error("port number forced a TLS/relay strategy", plan)
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					got := make([]byte, len(payload))
					if _, e := io.ReadFull(server, got); e != nil || !bytes.Equal(got, payload) {
						t.Error("application bytes changed", got, e)
						return
					}
					_, _ = server.Write([]byte("ordinary response"))
				}()
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(prefix); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(conn)
			if err != nil || string(response) != "ordinary response" || opens != 1 || actual.Policy.Action != flowpolicy.Direct {
				t.Fatal("ordinary exchange was replayed or relayed", string(response), opens, actual.Policy, err)
			}
		})
	}
}

func TestAutomaticNonTLSCannotWeakenOpaqueOrProtectedPolicy(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	q.Host, q.Secure = "", false
	tuple := destTuple("tcp", p.Destination.Addr().String(), 443)
	for _, reason := range []string{"ECH_OUTER_SNI_ONLY", "SNI_NOT_FOUND", "CLIENTHELLO_INCOMPLETE", "CLIENTHELLO_NO_PROGRESS", "REASSEMBLY_LIMIT", "CLIENTHELLO_INVALID"} {
		d := wp.ResolveDeferredDecision(c.Classify(cur.id, tuple), "", reason)
		plan := c.automaticApplicationPlan(cur, q, tuple, d, reason)
		if !d.Block && plan.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal("TLS ambiguity authorized DIRECT", reason, d, plan.Policy)
		}
	}
	// A fresh restrictive association revokes the capability before OPEN;
	// an earlier ordinary decision cannot retain permission for a shared IP.
	before := wp.ResolveDeferredDecision(c.Classify(cur.id, tuple), "", "NON_TLS_BINARY")
	c.browser.domains.replace(cur.network, []wp.DNSCacheEntry{{Name: "chatgpt.com", Address: tuple.Destination.Addr().String(), TTL: 30}}, nil, time.Now())
	if d := c.Classify(cur.id, tuple); d.AllowNonTLSDirect {
		t.Fatal("protected address association granted non-TLS bypass")
	}
	if plan := c.automaticApplicationPlan(cur, q, tuple, before, "NON_TLS_BINARY"); plan.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal("stale ordinary capability bypassed fresh protected association", plan.Policy)
	}
	c.browser.domains.replace(cur.network, nil, nil, time.Now())
	for _, mode := range []profiles.Mode{profiles.Direct, profiles.Manual, profiles.Block} {
		profile := cur.profile
		profile.Mode, profile.Custom, profile.RelayID = mode, true, "VPS-01"
		if err := c.Profiles.Upsert(profile); err != nil {
			t.Fatal(err)
		}
		if d := c.Classify(cur.id, tuple); d.AllowNonTLSDirect || d.OpenDeferred != nil {
			t.Fatal("explicit profile entered generic non-TLS handling", mode, d)
		}
	}
	profile := cur.profile
	profile.Custom, profile.Fallback = true, flowpolicy.Required
	if err := c.Profiles.Upsert(profile); err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(cur.id, tuple); d.AllowNonTLSDirect {
		t.Fatal("explicit required fallback became a binary bypass")
	}
}
