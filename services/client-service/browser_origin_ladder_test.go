package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/originpolicy"
	wp "github.com/buzzmean/veliq/platform/windows"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestCommonLadderDPIAndUnknownFailuresButNotOrdinaryOrProtected(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	for _, host := range []string{"discord.com", "x.com", "rutracker.org", "www.youtube.com"} {
		q.Host = host
		if !c.localLadderEligible(cur, q, p) {
			t.Fatal("known DPI not using common selector", host)
		}
		if !c.sharedScopeAllowed(youtubeScope(cur, q)) {
			t.Fatal("known DPI not shared", host)
		}
	}
	for _, host := range []string{"vk.ru", "google.com", "yandex.ru", "chatgpt.com", "claude.ai", "web.telegram.org", "instagram.com"} {
		q.Host = host
		if c.localLadderEligible(cur, q, p) {
			t.Fatal("ordinary/protected entered LOCAL", host)
		}
	}
	q.Host = "unknown.example.net"
	p.Policy.Source = "browser_domain"
	if c.sharedScopeAllowed(youtubeScope(cur, q)) {
		t.Fatal("private browsing name sent to shared cohort")
	}
	for i := 0; i < 2; i++ {
		c.observeDirectOpen(cur, q, p, context.DeadlineExceeded, time.Now())
	}
	if !c.localLadderEligible(cur, q, p) {
		t.Fatal("proven failed ordinary origin never gets LOCAL selection")
	}
}
func TestSignedOriginDataDrivesRouteWithoutTouchingImmutableFloors(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	data := localstrategy.BundledCatalog()
	d := originpolicy.Bundled()
	d.Rules = append(d.Rules, originpolicy.Rule{Group: "new-dpi", Kind: "DPI", Suffixes: []string{"dpi.example.net"}}, originpolicy.Rule{Group: "new-geo", Kind: "RELAY", Suffixes: []string{"geo.example.net"}})
	data.Origins = &d
	raw, _ := json.Marshal(data)
	if _, e := localstrategy.ParseCatalog(raw); e != nil {
		t.Fatal(e)
	}
	c.catalog.use(data, 4, "SIGNED_CONTROL_PLANE")
	q.Host = "dpi.example.net"
	if !c.localLadderEligible(cur, q, p) {
		t.Fatal("signed DPI rule ignored")
	}
	q.Host = "geo.example.net"
	if c.localLadderEligible(cur, q, p) {
		t.Fatal("signed geoblock desynced")
	}
	got := c.browserFlow(cur.profile, wp.ProcessIdentity{Path: q.Owner.Exe}, wp.Tuple{Protocol: "tcp", Destination: p.Destination}, q.Host, cur.network)
	if got.Action != flowpolicy.RelayRequired || got.Fallback != flowpolicy.Required {
		t.Fatal("signed GEO leaked", got)
	}
	// Dynamic required hints must be checked over the entire set BEFORE truncation.
	var index browserDomainIndex
	ip := netip.MustParseAddr("1.1.1.1")
	rows := []wp.DNSCacheEntry{}
	for _, host := range []string{"a.example.net", "b.example.net", "c.example.net", "d.example.net", "e.example.net", "f.example.net", "g.example.net", "h.example.net", "z.geo.example.net"} {
		rows = append(rows, wp.DNSCacheEntry{Name: host, Address: ip.String(), TTL: 60})
	}
	index.replace(cur.network, rows, nil, time.Now())
	e := index.profileEvidenceFor(cur.network, cur.profile.ID, ip, "", time.Now(), func(h string) bool { return c.browserOriginPolicy(h).Kind != "" })
	if len(e.Candidates) != 8 || !e.Restricted {
		t.Fatal("required ninth hint hidden", e)
	}
}
func TestColdDPIUsesRelayWhileSelectingAndOrdinaryStaysDirect(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	for _, host := range []string{"discord.com", "www.youtube.com", "x.com"} {
		q.Host = host
		calls := 0
		_, actual, e := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
			calls++
			if plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
				t.Error("cold DIRECT/LOCAL injected", host, plan)
			}
			return nil, errors.New("controlled failed open")
		})
		if e == nil || calls != 1 || actual.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal(host, calls, actual, e)
		}
	}
	q.Host = "vk.ru"
	if c.localLadderEligible(cur, q, p) {
		t.Fatal("ordinary origin delayed")
	}
}

func TestCommonLOCALScopeExcludesReservedAndLANAddresses(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "discord.com"
	for _, ip := range []string{"127.0.0.1", "192.168.88.252", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1"} {
		p.Destination = netip.AddrPortFrom(netip.MustParseAddr(ip), 443)
		if c.localLadderEligible(cur, q, p) {
			t.Fatal("reserved address got desync", ip)
		}
	}
}
