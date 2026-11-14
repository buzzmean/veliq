package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/ipc"
	"github.com/buzzmean/neexitlag/core/routing"
)

func TestDPIFieldEvidenceSurvivesBothRecordLimits(t *testing.T) {
	c, _, q, p := youtubeFixture(t)
	q.Owner.PID, q.Owner.Birth = 100, 200
	q.Owner.Exe, q.Owner.Profile = "chrome.exe", "test-profile"
	root := dpiFieldIdentity{q.Owner.PID, q.Owner.Birth}
	a := &c.browser.dpiField
	a.root, a.profile, a.owners = root, q.Owner.Profile, map[dpiFieldIdentity]bool{root: true}
	r := c.browser.youtube
	r.mu.Lock()
	id := r.addYoutubeRecordLocked(youtubeRecord{Domain: q.Host, Stage: "LOCAL"})
	for range 110 {
		r.addYoutubeRecordLocked(youtubeRecord{})
	}
	_, found := r.records[id]
	r.mu.Unlock()
	if found {
		t.Fatal("original LOCAL history did not evict fixture row")
	}
	row := a.localCDN(q, p.Destination.String(), "split1", 42, id)
	if row == nil {
		t.Fatal("LOCAL CDN not attributed to test Chrome")
	}
	for range dpiFieldRowLimit {
		a.dns(q, q.Host, "CONNECT_SYSTEM_RESOLVER", "DNS_RESPONSE", 1, 1)
	}
	const rx = 4 * 1024 * 1024
	m := &youtubeMeter{r: r, label: "field-fixture", stage: "LOCAL", id: id, transform: func() bool { return true },
		fieldAccount: func(tx, rx uint64) { a.localBytes(row, tx, rx) }}
	m.account(0, rx)
	page, err := a.page(0)
	if err != nil || page.Totals.LocalCDNRX != rx || page.Rows[0].RX != rx || page.Rows[0].ConnectionID != 42 ||
		page.Rows[0].RecordID != id || page.Totals.Omitted != 1 || page.Totals.DNS != dpiFieldRowLimit || page.Next != dpiFieldPageSize {
		t.Fatalf("field accounting or pagination lost bytes: %+v, %v", page.Totals, err)
	}
	last, err := a.page(dpiFieldRowLimit - 1)
	if err != nil || len(last.Rows) != 1 || last.Rows[0].Seq != dpiFieldRowLimit || last.Count != last.Next {
		t.Fatalf("last page lost DNS evidence: %+v %v", last, err)
	}
	wire, err := json.Marshal(page)
	if err != nil || len(wire) > ipc.MaxMessage-1024 {
		t.Fatalf("field IPC page too large: %d %v", len(wire), err)
	}
}

func TestDPIFieldAncillaryScopeAndDNS(t *testing.T) {
	enableDPILocalFixture(t)
	BrowserDPILocalField = "pc24-final"
	c, cur, q, p := youtubeFixture(t)
	q.Owner.PID, q.Owner.Birth, q.Owner.Exe, q.Owner.Profile = 100, 200, "chrome.exe", cur.profile.ID
	cur.id.PID, cur.id.CreationTime, cur.id.Path = q.Owner.PID, q.Owner.Birth, q.Owner.Exe
	root := dpiFieldIdentity{q.Owner.PID, q.Owner.Birth}
	a := &c.browser.dpiField
	a.root, a.profile, a.owners = root, cur.profile.ID, map[dpiFieldIdentity]bool{root: true}
	q.Ingress = "PAC_CONNECT"
	for _, host := range []string{"googleads.g.doubleclick.net", "static.doubleclick.net", "play.google.com"} {
		q.Host = host
		if !c.browserDPILocalRequest(cur, q) {
			t.Fatalf("test Chrome dependency was not scoped to LOCAL: %s", host)
		}
		background := q
		background.Owner.PID, background.Owner.Birth = 101, 199
		if c.browserDPILocalRequest(cur, background) {
			t.Fatalf("unrelated Chrome changed policy: %s", host)
		}
		var attempts int
		_, plan, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
			attempts++
			if plan.Policy.Action != flowpolicy.DirectPlus || plan.Policy.RelayID != "" {
				t.Errorf("unexpected relay policy: %+v", plan.Policy)
			}
			return nil, errors.New("fixture: origin unavailable")
		})
		if err == nil || attempts != browserDPILocalAttempts || plan.Policy.Action != flowpolicy.Block {
			t.Fatalf("unavailable auxiliary host did not stop after LOCAL: %s %d %+v %v", host, attempts, plan.Policy, err)
		}
		_, err = c.resolveDPIFieldDNS(context.Background(), q, func(_ context.Context, network, name string) ([]netip.Addr, error) {
			if network != "ip4" || name != host {
				t.Fatalf("unexpected DNS scope: %s %s", network, name)
			}
			return []netip.Addr{p.Destination.Addr()}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []string{"chatgpt.com", "gemini.google.com", "play.google.com.example", "other.doubleclick.net", "nested.static.doubleclick.net", "google.com"} {
		q.Host = host
		if c.dpiFieldAncillary(q) {
			t.Fatalf("unrelated host admitted: %s", host)
		}
	}
	page, err := a.page(0)
	if err != nil || page.Totals.DNS != 3 || page.Totals.RelayDNS != 0 || len(page.Rows) != 3 ||
		page.Rows[2].DNSPath != "CONNECT_SYSTEM_RESOLVER" || page.Rows[2].Host != "play.google.com" {
		t.Fatalf("CONNECT DNS evidence missing: %+v %v", page, err)
	}
	q.Host = "dns.google"
	p.Probe = "DPI_LOCAL_ENCRYPTED_RESOLVER"
	c.recordFieldResolverOpen(q, p, nil)
	page, err = a.page(3)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].DNSPath != "DIRECT_DOH_TUNNEL" || page.Rows[0].Result != "TLS_TUNNEL_OPENED" {
		t.Fatalf("DIRECT DoH tunnel evidence missing: %+v %v", page, err)
	}
}

type dpiFieldRelayFixture struct{}

func (dpiFieldRelayFixture) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("fixture provider open failure")
}
func (dpiFieldRelayFixture) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, errors.New("fixture provider open failure")
}

func TestDPIFieldRecordsFailedRelayOpenAndUnknownOwner(t *testing.T) {
	enableDPILocalFixture(t)
	BrowserDPILocalField = "pc24-final"
	c := New(context.Background())
	root := dpiFieldIdentity{100, 200}
	a := &c.browser.dpiField
	a.root, a.profile, a.owners, a.relayRows = root, "chrome", map[dpiFieldIdentity]bool{root: true}, make(map[dpiFieldRelayFlow]*dpiFieldRow)
	c.Engine.SetRelay("fixture-relay", dpiFieldRelayFixture{})
	f := routing.Flow{PID: root.PID, OwnerBirth: root.Birth, ProcessPath: "chrome.exe", ApplicationID: "chrome",
		Source: netip.MustParseAddrPort("127.0.0.1:50100"), Destination: netip.MustParseAddrPort("8.8.8.8:443"),
		OriginReason: "browser_dns_wire_doh", PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: "fixture-relay"}, BlockOnFailure: true}}
	if _, err := c.Engine.OpenTCP(context.Background(), f); err == nil {
		t.Fatal("fixture must fail before any relay bytes")
	}
	f.PID, f.OwnerBirth = 101, 0
	if _, err := c.Engine.OpenUDP(context.Background(), f); err == nil {
		t.Fatal("fixture must fail before any relay datagram")
	}
	f.OwnerBirth = 199
	_, _ = c.Engine.OpenTCP(context.Background(), f)
	q := browserproxy.Request{Owner: browserproxy.Owner{PID: root.PID, Birth: root.Birth, Exe: "chrome.exe", Profile: "chrome"}}
	a.dns(q, "example.com", "AUTHENTICATED_RELAY_DOH", "DNS_FAILED", 0, 1)
	page, err := a.page(0)
	if err != nil || len(page.Rows) != 3 || page.Totals.RelayOpens != 1 || page.Totals.UnattributedRelay != 1 ||
		page.Totals.RelayRX != 0 || page.Totals.RelayDNS != 1 || page.Totals.RelayDNSOpens != 1 ||
		page.Rows[0].Kind != "RELAY_OPEN" || page.Rows[1].Attribution != "UNATTRIBUTED" || page.Rows[2].Kind != "DNS" {
		t.Fatalf("failed relay/DNS attribution lost: %+v %v", page, err)
	}
	if _, err := a.page(-1); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}

func TestDPIFieldAuditAbsentInOrdinaryBuild(t *testing.T) {
	old := BrowserDPILocalField
	BrowserDPILocalField = ""
	t.Cleanup(func() { BrowserDPILocalField = old })
	c := New(context.Background())
	for _, method := range []string{"browser.dpi_local.begin", "browser.dpi_local.evidence"} {
		if _, err := c.HandleOwnerIPC(context.Background(), method, json.RawMessage(`{}`)); err == nil {
			t.Fatalf("ordinary build exposed %s", method)
		}
	}
}
