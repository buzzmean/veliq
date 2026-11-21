package clientservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestRiotSilentTLSUsesOtherDNSAddressBeforeRelay(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	cur.profile = profiles.Profile{ID: "riot-client", Name: "Riot Client", AppPreset: "riot-client", Mode: profiles.Auto, Executables: profiles.RiotLauncherExecutables()}
	q.Host = "sieve.services.riotcdn.net"
	q.Owner.Profile = cur.profile.ID
	p.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Source: "riot_direct_first"}
	p.Destination = netip.MustParseAddrPort("104.18.36.199:443")
	second := netip.MustParseAddrPort("172.64.151.57:443")
	p.DirectCandidates = []netip.AddrPort{p.Destination, second}
	server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified patch endpoint") }))
	var opens atomic.Int32
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		opens.Add(1)
		t.Logf("open %s action=%s", plan.Destination, plan.Policy.Action)
		if plan.Policy.Action != flowpolicy.Direct {
			t.Error("healthy other A must precede relay", plan)
		}
		if plan.Destination == p.Destination {
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(io.Discard, b) }()
			return a, nil
		}
		if plan.Destination != second {
			t.Error("unexpected candidate", plan.Destination)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	raw, _, err := c.openRiotPlan(context.Background(), cur, q, p, open)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	secure := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	if err = secure.Handshake(); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", "https://"+q.Host+"/", nil)
	if err = req.Write(secure); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "verified patch endpoint" {
		t.Fatal("not verified HTTPS result", err)
	}
	if opens.Load() != 2 || raw.(browserproxy.PlanReporter).CurrentPlan().Destination != second {
		t.Fatal("alternate not selected", opens.Load())
	}
	if !c.directAddressFailed(cur, q, p) {
		t.Fatal("silent endpoint not cached")
	}
	if c.directAddressFailed(cur, q, browserproxy.RetargetOrigin(p, second)) {
		t.Fatal("healthy peer poisoned")
	}
	if c.browser.directTimeouts.AddressFailed(c.directTimeoutKey(cur, q, p), time.Now().Add(11*time.Minute)) {
		t.Fatal("permanent pin")
	}
}
func TestRiotFirstOriginByteForbidsReplay(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "sieve.services.riotcdn.net"
	p.DirectCandidates = []netip.AddrPort{p.Destination, netip.MustParseAddrPort("172.64.151.57:443")}
	var opens atomic.Int32
	open := func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		opens.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			buf := make([]byte, 8192)
			b.Read(buf)
			b.Write([]byte{21, 3, 3, 0, 2, 2, 40})
		}()
		return a, nil
	}
	raw, _, e := c.openRiotPlan(context.Background(), cur, q, p, open)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	s := tls.Client(raw, &tls.Config{ServerName: q.Host, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	s.SetDeadline(time.Now().Add(3 * time.Second))
	if s.Handshake() == nil {
		t.Fatal("alert accepted")
	}
	if opens.Load() != 1 {
		t.Fatal("replay after alert", opens.Load())
	}
}
func TestRiotCaptureScopeDoesNotAdoptGames(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.mu.Lock()
	c.enabled = true
	c.mu.Unlock()
	id := wp.ProcessIdentity{PID: 5, CreationTime: 5, Path: `C:\Riot Games\Riot Client\RiotClientServices.exe`}
	d := c.Classify(id, wp.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:50000"), Destination: netip.MustParseAddrPort("104.18.36.199:443")})
	if !d.Deferred || d.OpenDeferred == nil {
		t.Fatal("launcher not deferred", d)
	}
	id.Path = `C:\Riot Games\VALORANT\VALORANT-Win64-Shipping.exe`
	d = c.Classify(id, wp.Tuple{Protocol: "tcp", Destination: netip.MustParseAddrPort("104.18.36.199:443")})
	if d.Deferred || !d.Route.Direct() {
		t.Fatal("game adopted launcher bypass", d)
	}
}

func TestRiotStatusDispatchAndNoBrowserReadinessContamination(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.browser.riot.activate("riot-client", true)
	_, err := c.browser.riot.begin(browserproxy.Request{Owner: browserproxy.Owner{Profile: "riot-client", PID: 5, Birth: 5, Exe: `C:\Riot Games\Riot Client\RiotClientServices.exe`}}, wp.Tuple{Protocol: "tcp", Destination: netip.MustParseAddrPort("104.18.36.199:443")})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.browser.native.records) != 0 {
		t.Fatal("Riot counted as browser")
	}
	if _, err = c.Handle(context.Background(), "riot.status", nil); err != nil {
		t.Fatal("handler unreachable", err)
	}
	if !clubReadMethod("riot.status") {
		t.Fatal("club diagnostics inaccessible")
	}
}

func TestRiotLateLocalRetryReportsActualRelay(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	cur.profile.ID = "riot-client"
	cur.profile.AppPreset = "riot-client"
	q.Host = "sieve.services.riotcdn.net"
	q.Owner.Profile = cur.profile.ID
	c.Backend = &youtubeTransformFixture{}
	p.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Source: "riot_direct_first"}
	c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(cur, q, p), time.Now())
	c.browser.youtube.confirmed(youtubeScope(cur, q), "LOCAL", youtubeLegacyOrder[0], time.Now())
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	var local, relay atomic.Int32
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action == flowpolicy.DirectPlus {
			local.Add(1)
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(io.Discard, b) }()
			return a, nil
		}
		if plan.Policy.Action != flowpolicy.RelayRequired {
			t.Error("unexpected route", plan.Policy)
		}
		relay.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	raw, _, err := c.openRiotPlan(context.Background(), cur, q, p, open)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	secure := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	if err = secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	if local.Load() != 1 || relay.Load() != 1 || raw.(browserproxy.PlanReporter).CurrentPlan().Policy.Action != flowpolicy.RelayRequired {
		t.Fatal("stale route after LOCAL retry", local.Load(), relay.Load(), raw.(browserproxy.PlanReporter).CurrentPlan())
	}
}
