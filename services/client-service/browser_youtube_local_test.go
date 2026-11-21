package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestYouTubeLocalCacheScopeTTLAndBoundedRecheck(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Now()
	k := youtubeKey{"net", "chrome", "googlevideo.com", 443, false}
	if stage, _ := r.choose(k, now); stage != "RELAY" {
		t.Fatal(stage)
	}
	r.failed(k, "LOCAL", youtubeLegacyOrder[0], "silent", now)
	if stage, _ := r.choose(k, now); stage != "RELAY" {
		t.Fatal(stage)
	}
	if v, ok := r.takeRecheck(k, now.Add(youtubeTrialCooldown+time.Second)); !ok || v.Next == 0 {
		t.Fatal(v, ok)
	}
	if _, ok := r.takeRecheck(k, now.Add(youtubeTrialCooldown+time.Second)); ok {
		t.Fatal("unbounded simultaneous rechecks")
	}
	if stage, _ := r.choose(k, now.Add(youtubeRetryAfter)); stage != "RELAY" {
		t.Fatal("foreground waits for background recheck", stage)
	}

	r.confirmed(k, "LOCAL", youtubeLegacyOrder[1], now)
	if stage, strategy := r.choose(k, now); stage != "LOCAL" || strategy != youtubeLegacyOrder[1] {
		t.Fatal(stage, strategy)
	}
	for _, other := range []youtubeKey{{"other", "chrome", "googlevideo.com", 443, false}, {"net", "edge", "googlevideo.com", 443, false}, {"net", "chrome", "youtube.com", 443, false}, {"net", "chrome", "googlevideo.com", 8443, false}, {"net", "chrome", "googlevideo.com", 443, true}} {
		if stage, _ := r.choose(other, now); stage != "RELAY" {
			t.Fatal("borrowed result", other)
		}
	}
	if stage, _ := r.choose(k, now.Add(youtubeLearnTTL)); stage != "RELAY" {
		t.Fatal("TTL pin")
	}
}
func youtubeFixture(t *testing.T) (*Controller, profilesResult, browserproxy.Request, browserproxy.Plan) {
	c, cur := timeoutFixture(t)
	cur.profile = profiles.Profile{ID: "chrome", Mode: profiles.Auto, BrowserTransport: "native", Executables: []string{`C:\Chrome\chrome.exe`}}
	cur.network = "net"
	q := browserproxy.Request{Owner: browserproxy.Owner{Exe: cur.profile.Executables[0], Profile: cur.profile.ID}, Host: "r1.googlevideo.com", Port: 443, Secure: true}
	p := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: netip.MustParseAddrPort("74.125.111.131:443"), Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: youtubeLadderSource}}
	c.network.Store(&wp.NetworkContext{Fingerprint: cur.network, ObservedAt: time.Now(), ConflictsObservedAt: time.Now()})
	return c, cur, q, p
}
func TestYouTubeAutomaticLocalEngineExactScopeAndHintsAreNotTrustedSNI(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.HintOnly = true
	id, e := c.youtubeEngine(cur, q, p, youtubeLegacyOrder[0])
	if e == nil || id == "" {
		t.Fatal("automatic engine absent")
	}
	q.HintOnly = false
	visibleID, _ := c.youtubeEngine(cur, q, p, youtubeLegacyOrder[0])
	if visibleID == id {
		t.Fatal("ECH/IP hint reused an SNI-scoped engine")
	}
	q.HintOnly = true
	if youtubeScope(cur, q) == youtubeScope(cur, browserproxy.Request{Host: q.Host, Port: q.Port}) {
		t.Fatal("hint-only and observed-SNI route learning merged")
	}

	m := localstrategy.Metadata{Application: q.Owner.Exe, Domain: "unrelated-ech-outer.example", Protocol: "tcp", Destination: p.Destination, StrategyID: id}
	if !e.Match(m) {
		t.Fatal("exact DNS-associated tuple not eligible")
	}
	m.Destination = netip.MustParseAddrPort("74.125.111.132:443")
	if e.Match(m) {
		t.Fatal("different IP matched")
	}
	m.Destination = p.Destination
	m.Application = `C:\Games\cs2.exe`
	if e.Match(m) {
		t.Fatal("game matched")
	}
	q.OriginAmbiguous = true
	if youtubeLadderEligible(q, p) {
		t.Fatal("ambiguous origin eligible")
	}
	for _, domain := range []string{"chatgpt.com", "claude.ai", "web.telegram.org", "vk.ru", "google.com", "youtube.com.evil.example"} {
		q.Host = domain
		q.OriginAmbiguous = false
		if youtubeLadderEligible(q, p) {
			t.Fatal("unrelated group", domain)
		}
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: cur.network, ObservedAt: time.Now(), ConflictsObservedAt: time.Now(), Conflicts: []string{"winws"}})
	if id, e = c.youtubeEngine(cur, q, p, youtubeLegacyOrder[0]); id != "" || e != nil {
		t.Fatal("conflict guard bypass")
	}
}
func TestYouTubeUnprovenForegroundDoesNotWaitForDirectOrLocal(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.settings.YouTubeViaRelay = false
	var actions []flowpolicy.Action
	_, _, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		actions = append(actions, plan.Policy.Action)
		return nil, errors.New("injected open failure")
	})
	if err == nil || len(actions) != 1 || actions[0] != flowpolicy.RelayRequired {
		t.Fatal(actions, err)
	}
	if stage, _ := c.browser.youtube.choose(youtubeScope(cur, q), time.Now()); stage != "RELAY" {
		t.Fatal(stage)
	}

}

func TestYouTubeACKHelloAndUntransformedTrafficCannotLearnLocalSuccess(t *testing.T) {
	r := newYoutubeRuntime()
	key := youtubeKey{"net", "chrome", "googlevideo.com", 443, false}
	r.stats["LOCAL:fake5"] = youtubeStage{Stage: "LOCAL", Strategy: "fake5"}
	r.records[1] = youtubeRecord{ID: 1, Stage: "LOCAL"}
	m := &youtubeMeter{r: r, id: 1, label: "LOCAL:fake5", key: key, stage: "LOCAL", strategy: "fake5", postHelloWrite: true, started: time.Now().Add(-time.Second), transform: func() bool { return false }}
	hello := append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)
	m.wire.ObserveOrigin(hello)
	m.account(2000, uint64(len(hello)))
	if len(r.cache) != 0 {
		t.Fatal("ServerHello alone learned health")
	}
	m.account(0, 70*1024)
	if len(r.cache) != 0 {
		t.Fatal("unapplied local strategy learned success")
	}
	m = &youtubeMeter{r: r, id: 1, label: "LOCAL:fake5", key: key, stage: "LOCAL", strategy: "fake5", postHelloWrite: true, started: time.Now().Add(-time.Second), transform: func() bool { return true }}
	m.wire.ObserveOrigin(hello)
	m.account(2000, 70*1024)
	if v := r.cache[key]; v.Stage != "LOCAL" || v.Strategy != "fake5" {
		t.Fatal(v)
	}
	m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	if v := r.cache[key]; v.Stage != "RELAY" {
		t.Fatal("degraded confirmed local stayed healthy", v)
	}
}
func TestYouTubeSixteenKBGapIsHintForNextFlowAndDoesNotCloseOrReplay(t *testing.T) {
	r := newYoutubeRuntime()
	key := youtubeKey{"net", "chrome", "googlevideo.com", 443, false}
	r.records[1] = youtubeRecord{ID: 1}
	m := &youtubeMeter{r: r, id: 1, key: key, stage: "LOCAL", strategy: youtubeLegacyOrder[0], tx: 2000, rx: 20 * 1024, lastReply: time.Now().Add(-5 * time.Second)}
	m.progressGap(time.Now())
	if r.cache[key].Stage != "RELAY" {
		t.Fatal("gap ignored")
	}
	if r.records[1].Reason != "EARLY_PROGRESS_GAP_HINT_NEXT_CONNECTION_ONLY" {
		t.Fatal("claimed definite HTTP failure")
	}
}

type youtubeTransformFixture struct{ nativeBackendFixture }

func (*youtubeTransformFixture) BrowserTransformApplied(wp.ProcessIdentity, netip.AddrPort, netip.AddrPort) bool {
	return true
}

func TestYouTubeSelectedTLSHTTPExchangeThroughLocalAndWarmCache(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.Backend = &youtubeTransformFixture{}
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	var direct, local, relay atomic.Int32
	open := func(ctx context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		switch p.Policy.Action {
		case flowpolicy.Direct:
			direct.Add(1)
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(io.Discard, b) }()
			return a, nil
		case flowpolicy.DirectPlus:
			local.Add(1)
		default:
			relay.Add(1)
			return nil, errors.New("relay must not be used")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	c.browser.youtube.confirmed(youtubeScope(cur, q), "LOCAL", youtubeLegacyOrder[0], time.Now())
	for trial := 0; trial < 2; trial++ {
		start := time.Now()
		conn, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
		if err != nil {
			t.Fatal(err)
		}
		secure := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: q.Host, MinVersion: tls.VersionTLS12})
		secure.SetDeadline(time.Now().Add(4 * time.Second))
		if err = secure.Handshake(); err != nil {
			t.Fatal("real TLS handshake", err)
		}
		req, _ := http.NewRequest("GET", "https://"+q.Host+"/video-fixture", nil)
		req.Close = true
		if err = req.Write(secure); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(secure), req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		secure.Close()
		if err != nil || response.StatusCode != 200 || len(body) != 131072 {
			t.Fatal("not real HTTP success", len(body), err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatal("cold budget", elapsed)
		} else {
			t.Logf("trial=%d verified TLS+HTTP+128KiB elapsed=%v", trial, elapsed)
		}
	}
	if direct.Load() != 0 || local.Load() != 2 || relay.Load() != 0 {
		t.Fatal("warm route not learned", direct.Load(), local.Load(), relay.Load())
	}
	s := c.browser.youtube.snapshot()
	for _, v := range s.Stages {
		if v.Stage == "RELAY" && v.RX > 0 {
			t.Fatal("relay payload despite local success")
		}
	}
}

func TestYouTubeOnlyHintsExaminedBeforeTruncationAndNeverBorrowProtectedDomain(t *testing.T) {
	var x browserDomainIndex
	now := time.Now()
	ip := netip.MustParseAddr("74.125.111.131")
	rows := []wp.DNSCacheEntry{}
	for _, name := range []string{"a.googlevideo.com", "b.googlevideo.com", "c.googlevideo.com", "d.googlevideo.com", "e.googlevideo.com", "f.googlevideo.com", "g.googlevideo.com", "h.googlevideo.com", "z.chatgpt.com"} {
		rows = append(rows, wp.DNSCacheEntry{Name: name, Address: ip.String(), TTL: 60})
	}
	x.replace("net", rows, nil, now)
	e := x.profileEvidence("net", "chrome", ip, "", now)
	if e.YoutubeOnly || !e.Ambiguous {
		t.Fatal("truncated away protected association", e)
	}
	x.replace("net", rows[:8], nil, now)
	e = x.profileEvidence("net", "chrome", ip, "", now)
	if !e.YoutubeOnly || !e.Ambiguous {
		t.Fatal("all-YouTube hint group not recognised", e)
	}
	e = x.profileEvidence("net", "chrome", ip, "chatgpt.com", now)
	if e.YoutubeOnly {
		t.Fatal("protected outer downgraded")
	}
}

func TestYouTubePreservesVerifiedConfiguredBaselineAsFirstLocalStrategy(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "www.youtube.com"
	entries, selected, err := localstrategy.PresetProfiles("youtube", q.Owner.Exe, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: entries}); err != nil {
		t.Fatal(err)
	}
	cur.profile.LocalStrategyID = selected
	cur.profile.AutoNetwork = cur.network
	cur.profile.AutoRevision = c.baselineRevision(cur.profile)
	p.Policy = c.browserFlow(cur.profile, wp.ProcessIdentity{Path: q.Owner.Exe}, wp.Tuple{Protocol: "tcp", Destination: p.Destination}, q.Host, cur.network)
	if p.Policy.Source != "configured_baseline" {
		t.Fatal("fixture lacks verified baseline", p.Policy)
	}
	a, b := net.Pipe()
	defer b.Close()
	calls := 0
	conn, actual, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		calls++
		if plan.Policy.Action != flowpolicy.DirectPlus || plan.Policy.Strategy != selected {
			t.Fatal("working baseline replaced", plan)
		}
		return a, nil
	})
	if err != nil || calls != 1 || actual.Policy.Strategy != selected {
		t.Fatal(actual, err)
	}
	conn.Close()
}

func TestYouTubeShortCDNRootsNeverQualify(t *testing.T) {
	for _, status := range []int{200, 204, 403, 404, 405, 451} {
		if youtubeTransferOK(browserproxy.ProbeResult{Status: status, TLSVersion: 0x0304, Bytes: 100 * 1024, BodyBytes: 1400}) {
			t.Fatal("short response authorized LOCAL", status)
		}
	}
	if youtubeTransferOK(browserproxy.ProbeResult{Status: 200, TLSVersion: 0x0304, BodyBytes: 65536}) {
		t.Fatal("strict >64KiB not enforced")
	}
	if !youtubeTransferOK(browserproxy.ProbeResult{Status: 200, TLSVersion: 0x0304, BodyBytes: 65537}) {
		t.Fatal("real response rejected")
	}
}

func youtubeTLSHTTPFixture(t *testing.T, host string, handlers ...http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(280 * time.Millisecond)
		w.Header().Set("Content-Length", "131072")
		w.Write(bytes.Repeat([]byte("v"), 131072))
	}))
	if len(handlers) > 0 {
		handler = handlers[0]
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, roots
}

func TestGuardedCDNRealTLSHTTPThreeTrialsThenWarmLOCAL(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.Backend = &youtubeTransformFixture{}
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	r := c.browser.youtube
	k := youtubeScope(cur, q)
	id := r.order[0]
	now := time.Now()
	r.cache[k] = youtubeLearn{Stage: "RELAY", Qualified: id, Until: now.Add(youtubeLearnTTL)}
	r.qualifications[youtubeQualification{k.Network, k.Profile, id, k.HintOnly}] = now.Add(youtubeLearnTTL)
	usage := c.relayUsage()
	peer := usage.beginVideo(videoPerformance{Port: q.Port, Network: cur.network, Profile: cur.profile.ID, Domain: q.Host, Started: now})
	usage.mu.Lock()
	usage.videoIO(peer, 100, cdnStrongBytes+1, now)
	usage.mu.Unlock()
	local := 0
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action != flowpolicy.DirectPlus {
			t.Fatal("unexpected route", plan.Policy)
		}
		local++
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	for trial := 0; trial < 4; trial++ {
		// Virtual expiry of the tested cooldown; no wall-clock three-minute sleeps.
		r.mu.Lock()
		v := r.cache[k]
		v.Retry = time.Time{}
		v.TrialAfter = time.Time{} // Same virtual cooldown clock; production cannot bypass it.
		r.cache[k] = v
		r.mu.Unlock()
		conn, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
		if err != nil {
			t.Fatal(err)
		}
		secure := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: q.Host, MinVersion: tls.VersionTLS12})
		secure.SetDeadline(time.Now().Add(3 * time.Second))
		if err = secure.Handshake(); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", "https://"+q.Host+"/video-fixture", nil)
		req.Close = true
		if err = req.Write(secure); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(secure), req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		secure.Close()
		if err != nil || resp.StatusCode != 200 || len(body) != 131072 {
			t.Fatal("not real TLS+HTTP body", len(body), err)
		}
		stage, _ := r.choose(k, time.Now())
		if (stage == "LOCAL") != (trial >= 2) {
			t.Fatal("wrong promotion", trial, stage, r.snapshot())
		}
	}
	if local != 4 || r.snapshot().Selection.Trials != 3 || r.snapshot().Selection.TrialSuccesses != 3 {
		t.Fatal(local, r.snapshot())
	}
}

type eofControlProbeConn struct{ net.Conn }

func (*eofControlProbeConn) Read([]byte) (int, error) { return 0, io.EOF }
func TestShortControlEOFDoesNotInvalidatePublicProofOrConfirmCDN(t *testing.T) {
	for _, trial := range []bool{false, true} {
		r := newYoutubeRuntime()
		k := youtubeKey{"net", "chrome", "youtube.com", 443, false}
		id := r.order[0]
		r.confirmed(k, "LOCAL", id, time.Now())
		v := r.cache[k]
		v.Reason = "BACKGROUND_PUBLIC_REDIRECT_CONTROL_NOT_BULK_PROOF"
		r.cache[k] = v
		r.records[1] = youtubeRecord{ID: 1, Stage: "LOCAL"}
		m := &youtubeMeter{Conn: &eofControlProbeConn{}, r: r, id: 1, key: k, stage: "LOCAL", strategy: id, tx: 2000, rx: 7000, trial: trial, witnessChecked: true, applied: true, transform: func() bool { return true }}
		hello := append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)
		m.wire.ObserveOrigin(hello)
		if trial {
			v := r.cache[k]
			v.Stage = "RELAY"
			v.Confirmed = false
			r.cache[k] = v
		}
		if _, e := m.Read(make([]byte, 100)); !errors.Is(e, io.EOF) {
			t.Fatal(e)
		}
		if !trial && (r.cache[k].Stage != "LOCAL" || r.records[1].Reason != "SHORT_TLS_CLOSE_WITH_PUBLIC_CONTROL_PROOF") {
			t.Fatal("control EOF poisoned route", r.cache[k], r.records[1])
		}
		if trial && (r.cache[k].Stage != "RELAY" || m.healthy || m.failed) {
			t.Fatal("short unproven CDN EOF became success or failure")
		}
		if m.healthy {
			t.Fatal("short response became bulk health")
		}
	}
}
