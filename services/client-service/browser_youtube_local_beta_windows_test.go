//go:build windows

package clientservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func newYouTubeLocalBetaRouteFixture(t *testing.T) (*Controller, profilesResult, browserproxy.Request, browserproxy.Plan) {
	t.Helper()
	c, cur, q, p := youtubeFixture(t)
	id := cdnColdOwner(t)
	sid, err := wp.ProcessUserSID(id)
	if err != nil {
		t.Fatal(err)
	}
	c.BrowserOwnerSID, cur.id = sid, id
	if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
		t.Fatal(err)
	}
	cur.profile.Executables = []string{id.Path}
	cur.profile.Name = "Managed Chrome test"
	if err := c.Profiles.Upsert(cur.profile); err != nil {
		t.Fatal(err)
	}
	c.Backend = &youtubeTransformFixture{nativeBackendFixture{hotBackendFixture: hotBackendFixture{ready: true}}}
	c.youtubeLocalBeta.setGeneration(true)
	q.Owner = browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: cur.profile.ID}
	q.Ingress = "PAC_CONNECT"
	p.YouTubeLocalGeneration = c.youtubeLocalBetaOriginScope(q)
	p.Policy.Source = youTubeLocalBetaSource
	p.FirstFlightManaged = true
	if p.YouTubeLocalGeneration == 0 {
		t.Fatal("real Windows owner not admitted")
	}
	return c, cur, q, p
}

func TestYouTubeLocalBetaRouteTriesAlternateAfterSilenceAndReusesIt(t *testing.T) {
	c, cur, q, p := newYouTubeLocalBetaRouteFixture(t)
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	primary := youtubeLegacyOrder[0]
	c.browser.youtube.confirmed(youtubeScope(cur, q), "LOCAL", primary, time.Now())
	var opens, forbidden atomic.Int32
	open := func(ctx context.Context, request browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if request.Host != q.Host || plan.Destination != p.Destination || plan.Policy.Action != flowpolicy.DirectPlus ||
			plan.Policy.Fallback != flowpolicy.FailBlock || plan.Policy.RelayID != "" {
			forbidden.Add(1)
			return nil, errors.New("unexpected upstream")
		}
		if opens.Add(1) == 1 {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				_, _ = io.Copy(io.Discard, b)
			}()
			return a, nil
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	for exchange := 0; exchange < 2; exchange++ {
		raw, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		conn := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: q.Host, MinVersion: tls.VersionTLS12})
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("GET", "https://"+q.Host+"/video-fixture", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Close = true
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatal(err)
		}
		bytes, err := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		conn.Close()
		if err != nil || response.StatusCode != 200 || bytes != 131072 {
			t.Fatalf("TLS/HTTP status=%d bytes=%d err=%v", response.StatusCode, bytes, err)
		}
	}
	events := c.browser.youtube.cdnDecisionSnapshot().Events
	if opens.Load() != 3 || forbidden.Load() != 0 || len(events) != 7 {
		t.Fatalf("opens=%d forbidden=%d events=%+v", opens.Load(), forbidden.Load(), events)
	}
	if events[0].Reason != "LEARNED_LOCAL" || events[0].Strategy != primary || events[2].Reason != "ORIGIN_SILENT" ||
		events[4].Phase != "OPENED" || events[4].Stage != "LOCAL" || events[4].ConnectionID != events[0].ConnectionID ||
		events[4].Strategy == primary || events[5].Reason != "LEARNED_LOCAL" || events[5].Strategy != events[4].Strategy ||
		events[5].ConnectionID == events[0].ConnectionID {
		t.Fatalf("first flight or warm selection mismatch: %+v", events)
	}
	if elapsed := events[2].At.Sub(events[1].At); elapsed < 850*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("first flight timeout mismatch: %v", elapsed)
	}
	status := c.youtubeLocalBetaStatus()
	if status.LocalCDNRX < 2*131072 || status.LastFailure != "" {
		t.Fatalf("beta counters lost verified upstream bytes: %+v", status)
	}
	if stage, strategy := c.browser.youtube.choose(youtubeScope(cur, q), time.Now()); stage != "LOCAL" || strategy != primary {
		t.Fatalf("beta updated ordinary learning: %s %s", stage, strategy)
	}
	t.Logf("900ms first flight -> alternate LOCAL -> warm LOCAL; LOCAL RX=%d; VPS opens=%d", status.LocalCDNRX, forbidden.Load())
}

func TestYouTubeLocalBetaLocalDNSDoesNotUseRelayAndOldPlanCannotOpen(t *testing.T) {
	c, cur, q, p := newYouTubeLocalBetaRouteFixture(t)
	q.Host = "youtubei.googleapis.com"
	query, reply := brokerWire(t, q.Host)
	system, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	go func() {
		buf := make([]byte, 8192)
		if _, peer, err := system.ReadFrom(buf); err == nil {
			_, _ = system.WriteTo(reply, peer)
		}
	}()
	tuple := policyTuple("udp", 53)
	tuple.Destination = system.LocalAddr().(*net.UDPAddr).AddrPort()
	work, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := c.exchangeBrowserDNS(work, cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
		t.Error("recognized YouTube DNS attempted relay")
		return nil, errors.New("unexpected relay")
	})
	if err != nil || len(out) == 0 || c.youtubeLocalBetaStatus().LocalDNSQueries != 1 {
		t.Fatalf("local DNS response=%d err=%v status=%+v", len(out), err, c.youtubeLocalBetaStatus())
	}
	for _, host := range []string{"doubleclick.net", "play.google.com", "dns.google", "chatgpt.com", "discord.com", "youtu.be.evil.example", "74.125.111.131"} {
		q.Host = host
		if c.youtubeLocalBetaOriginScope(q) != 0 {
			t.Errorf("name crossed YouTube policy boundary: %s", host)
		}
	}
	q.Host = "www.youtube.com"
	rejectOpen := func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		t.Error("stale plan attempted upstream OPEN")
		return nil, errors.New("unexpected open")
	}
	c.youtubeLocalBeta.setGeneration(false)
	if _, _, err = c.openBrowserPlan(work, cur, q, p, rejectOpen); !errors.Is(err, errYouTubeLocalScopeChanged) {
		t.Fatalf("OFF accepted previous beta plan: %v", err)
	}
	c.youtubeLocalBeta.setGeneration(true)
	p.YouTubeLocalGeneration = 0
	if _, _, err = c.openBrowserPlan(work, cur, q, p, rejectOpen); !errors.Is(err, errYouTubeLocalScopeChanged) {
		t.Fatalf("ON accepted ordinary plan from possible relay DNS: %v", err)
	}
	t.Log("named API DNS stayed local; unrelated, protected and shared DNS hosts unchanged; stale plans rejected on OFF and ON")
}

func TestYouTubeLocalBetaPreservesBlocksAndHasBoundedNoRelayFailure(t *testing.T) {
	c, cur, q, p := newYouTubeLocalBetaRouteFixture(t)
	var actions []flowpolicy.Action
	open := func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		actions = append(actions, plan.Policy.Action)
		if plan.Policy.Fallback != flowpolicy.FailBlock || plan.Policy.RelayID != "" {
			t.Errorf("relay candidate or fallback leaked: %+v", plan.Policy)
		}
		return nil, errors.New("fixture refuses all upstreams")
	}
	_, blocked, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
	if err == nil || blocked.Policy.Reason != "DPI_LOCAL_NO_WORKING_STRATEGY" ||
		len(actions) != youTubeLocalBetaAttempts || actions[len(actions)-1] != flowpolicy.Direct ||
		c.youtubeLocalBetaStatus().LastFailure != "DPI_LOCAL_NO_WORKING_STRATEGY" {
		t.Fatalf("bounded failure or local direct fallback missing: %+v actions=%+v err=%v", blocked, actions, err)
	}
	for _, action := range actions[:len(actions)-1] {
		if action != flowpolicy.DirectPlus {
			t.Fatalf("no candidate switch: %v", actions)
		}
	}
	for _, action := range []flowpolicy.Action{flowpolicy.Block, flowpolicy.RelayRequired} {
		cur.profile.Rules = []flowpolicy.Rule{{ID: "explicit", Protocol: "tcp", Domains: []string{q.Host}, Action: action, RelayID: "VPS-01"}}
		_, blocked, err = c.openBrowserPlan(context.Background(), cur, q, p, open)
		if err == nil || blocked.Policy.Action != flowpolicy.Block || len(actions) != youTubeLocalBetaAttempts {
			t.Fatalf("explicit %s opened an upstream: %+v actions=%+v err=%v", action, blocked, actions, err)
		}
	}
	q.Ingress = "NATIVE_TCP"
	if generation := c.youtubeLocalBetaNativeScope(q, cur, p.Destination, ""); generation == 0 {
		t.Fatal("identified native YouTube must fail closed with no CONNECT authority")
	}
	q.Host = ""
	q.HintOnly = true
	if generation := c.youtubeLocalBetaNativeScope(q, cur, p.Destination, ""); generation != 0 {
		t.Fatal("genuinely unidentified flow must keep ordinary routing")
	}
	t.Log("four LOCAL/DIRECT candidates and no relay; explicit block/relay and unidentified native origins preserve scope")
}

func TestYouTubeLocalBetaPlainDirectWorksWhenLocalTransformsCannotOpen(t *testing.T) {
	c, cur, q, p := newYouTubeLocalBetaRouteFixture(t)
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	opens := 0
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		opens++
		if plan.Policy.Action != flowpolicy.Direct {
			return nil, errors.New("local transform refused")
		}
		if plan.Policy.RelayID != "" || plan.Policy.Fallback != flowpolicy.FailBlock {
			t.Fatalf("unsafe direct candidate: %+v", plan.Policy)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	dial := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		conn, actual, err := c.openBrowserPlan(ctx, cur, q, p, open)
		if err == nil && actual.Policy.Action != flowpolicy.Direct {
			conn.Close()
			t.Errorf("unexpected route: %+v", actual.Policy)
			return nil, errors.New("unexpected route")
		}
		return conn, err
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: dial,
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}}
	for attempt := 0; attempt < 2; attempt++ {
		response, err := client.Get("https://" + q.Host + "/video-fixture")
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || n != 131072 || response.StatusCode != http.StatusOK {
			t.Fatalf("direct HTTP result status=%d bytes=%d err=%v", response.StatusCode, n, err)
		}
	}
	events := c.browser.youtube.cdnDecisionSnapshot().Events
	if opens != youTubeLocalBetaAttempts+1 || events[len(events)-2].Reason != "LEARNED_DIRECT" {
		t.Fatalf("working plain direct not reused: opens=%d events=%+v", opens, events)
	}
	if status := c.youtubeLocalBetaStatus(); status.LocalCDNRX != 0 {
		t.Fatalf("plain DIRECT bytes claimed as transformed LOCAL: %+v", status)
	}
}

func TestYouTubeLocalBetaEndpointDenialIsExact(t *testing.T) {
	c, cur, q, p := newYouTubeLocalBetaRouteFixture(t)
	r := c.browser.youtube
	ordinary := youtubeScope(cur, q)
	key := ordinary
	key.Profile = "youtube-local-only:" + ordinary.Profile
	primary := youtubeLegacyOrder[0]
	now := time.Now()
	r.confirmed(ordinary, "LOCAL", primary, now)
	bad := cdnEndpoint{q.Host, p.Destination.String()}
	good := cdnEndpoint{q.Host, netip.MustParseAddrPort("74.125.111.132:443").String()}
	r.noteEndpointFailure(key, primary, bad, "ORIGIN_SILENT", now)
	r.mu.Lock()
	defer r.mu.Unlock()
	if pair := r.youtubeLocalBetaCandidatesLocked(key, ordinary, bad, false, now); len(pair) == 0 || pair[0].id == primary {
		t.Fatalf("previously refused strategy used for exact endpoint: %+v", pair)
	}
	if pair := r.youtubeLocalBetaCandidatesLocked(key, ordinary, good, false, now); len(pair) == 0 || pair[0].id != primary {
		t.Fatalf("failure poisoned another address: %+v", pair)
	}
}
