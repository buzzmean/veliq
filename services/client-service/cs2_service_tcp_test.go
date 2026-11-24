package clientservice

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestCS2TCPServiceStrictNativeDirectAndProtectedHints(t *testing.T) {
	c, owner, p := cs2GameFixture(t)
	p.Mode = profiles.Auto
	raw, _ := json.Marshal(p)
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	n := c.network.Load()
	now := time.Now()
	// Legacy learned domains and a globally preferred relay must not re-enter
	// the ordinary game's TCP service lane, even when the route table is warm.
	key := c.learnKey(p, n.Fingerprint, "tcp", "steam-service.test", 443)
	if err := c.AutoLearned.Record(flowpolicy.Learned{Key: key, Result: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}, Success: true, Observed: now, Expires: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	preferGameRelay(c)
	c.browser.domains.replace(n.Fingerprint, []wp.DNSCacheEntry{{Address: "93.184.216.34", Name: "steam-service.test", TTL: 60}, {Address: "93.184.216.35", Name: "api.openai.com", TTL: 60}, {Address: "2606:4700:4700::1111", Name: "api.openai.com", TTL: 60}}, nil, now)
	for _, tc := range []struct {
		ip    string
		port  uint16
		block bool
	}{
		{"93.184.216.34", 443, false}, {"93.184.216.35", 443, true}, {"2606:4700:4700::1111", 443, true},
		{"93.184.216.34", 80, false}, {"93.184.216.34", 27017, false}, {"10.0.0.9", 27017, false}, {"93.184.216.35", 53, false},
	} {
		d := c.Classify(owner, destTuple("tcp", tc.ip, tc.port))
		if !d.NewConnectionsOnly || !d.CS2Auto || d.Block != tc.block || d.BlockOnFailure != tc.block || d.Group != p.ID || !d.Route.Direct() || d.Local != nil || d.GameUDP != nil || d.OpenDeferred != nil || d.ResolveDomain != nil || d.Deferred || d.ProbeDirect || d.Flow.PinnedPolicy == nil || d.Flow.PinnedPolicy.Block != tc.block || d.Flow.PinnedPolicy.Route.RelayID != "" {
			t.Fatalf("TCP %s:%d block=%t decision=%+v", tc.ip, tc.port, tc.block, d)
		}
	}
	for _, tc := range []struct {
		host string
		want flowpolicy.Action
	}{{"steam-service.test", flowpolicy.Direct}, {"api.openai.com", flowpolicy.Block}, {"93.184.216.35", flowpolicy.Block}} {
		plan, ok := c.cs2ProxyPlan(owner, browserproxy.Request{Host: tc.host, Port: 443})
		if !ok || plan.Enabled || plan.Policy.Action != tc.want || plan.Policy.RelayID != "" {
			t.Fatal(tc, plan)
		}
	}
	other := owner
	other.Path = `C:\Elsewhere\cs2.exe`
	if _, ok := c.cs2ProxyPlan(other, browserproxy.Request{Host: "steam-service.test", Port: 443}); ok {
		t.Fatal("wrong owner inherited proxy lane")
	}
}

func TestCS2ProxyOpensOnlyRequestedService(t *testing.T) {
	controller, owner, p := cs2GameFixture(t)
	p.Mode = profiles.Auto
	raw, _ := json.Marshal(p)
	if _, err := controller.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	q := browserproxy.Request{Owner: browserproxy.Owner{Profile: p.ID}, Host: "localhost", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
	conn, err := controller.openCS2ProxyDirect(context.Background(), owner, q)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != l.Addr().String() {
		t.Fatalf("connected to %v", conn.RemoteAddr())
	}
	// A hostname passes the initial plan, but its selected IP must still
	// obey a saved operator CIDR policy before the first outgoing SYN.
	p.Rules = []flowpolicy.Rule{{ID: "restricted-address", Protocol: "tcp", CIDRs: []string{"127.0.0.0/8"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}
	if err := controller.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	if blocked, err := controller.openCS2ProxyDirect(context.Background(), owner, q); err == nil {
		blocked.Close()
		t.Fatal("resolved IPv4 address ignored the existing relay-only rule")
	}
	p.Rules = nil
	if err := controller.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	q.Owner.Profile = "different-profile"
	if conn, err := controller.openCS2ProxyDirect(context.Background(), owner, q); err == nil {
		conn.Close()
		t.Fatal("opened directly after losing the verified owner profile")
	}
}
