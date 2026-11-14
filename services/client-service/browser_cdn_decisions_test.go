package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/ipc"
)

func TestCDNDecisionReportsDenialWhenNativeStatusIsTruncated(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	r := c.browser.youtube
	now := time.Now()
	// A full subgroup cache cannot retain this connection's admission check.
	for i := range 256 {
		key := youtubeKey{Network: "net", Profile: strings.Repeat("p", 128), Domain: strings.Repeat("d", 180), Port: uint16(i + 1)}
		r.cache[key] = youtubeLearn{Until: now.Add(youtubeLearnTTL), Reason: strings.Repeat("r", 256)}
	}
	for id := uint64(1); id <= 64; id++ {
		r.records[id] = youtubeRecord{ID: id, Domain: strings.Repeat("d", 253), Profile: strings.Repeat("p", 128)}
	}
	r.seq = 64
	for i := 0; i < 128; i++ {
		label := strings.Repeat("s", 96) + time.Unix(int64(i), 0).Format(time.RFC3339)
		r.stats[label] = youtubeStage{Service: "youtube-media", Stage: "LOCAL", Strategy: label}
	}
	if _, _, err := c.openYoutubeLadder(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action != flowpolicy.RelayRequired {
			t.Errorf("unexpected route: %v", plan.Policy.Action)
		}
		return nil, errors.New("fixture relay unavailable")
	}); err == nil {
		t.Fatal("expected failed relay open")
	}
	if _, ok := r.cache[youtubeScope(cur, q)]; ok {
		t.Fatal("fixture unexpectedly retained the admission cache entry")
	}
	if snapshot := c.nativeSnapshot(); !snapshot.Truncated || snapshot.YoutubeLocal.CacheOmitted <= len(r.cache)-24 {
		t.Fatalf("fixture did not trim the native cache: truncated=%v omitted=%d", snapshot.Truncated, snapshot.YoutubeLocal.CacheOmitted)
	}
	c.clubMode.Store(true)
	data, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.decisions", nil)
	if err != nil {
		t.Fatal(err)
	}
	events := data.(cdnDecisionSnapshot).Events
	if len(events) != 2 {
		t.Fatal(events)
	}
	selected, failed := events[0], events[1]
	if selected.Phase != "SELECTED" || selected.Stage != "RELAY" || selected.Admission != "NO_QUALIFIED_STRATEGY" ||
		selected.Selection == nil || selected.Selection.Scope != youtubeScope(cur, q) || selected.Selection.Cache != nil ||
		selected.Selection.Trial == nil || selected.Selection.Trial.Cache != nil ||
		selected.Host != q.Host || selected.Destination != p.Destination.String() || failed.ConnectionID != selected.ConnectionID ||
		failed.Phase != "OPEN_FAILED" || failed.Stage != "RELAY" || failed.Reason != "" || failed.RecordID == 0 || failed.Selection != nil {
		t.Fatal(events)
	}
}

func TestCDNDecisionReportsPrimaryRelay(t *testing.T) {
	for _, tc := range []struct {
		name, reason, admission string
		blocked                 bool
	}{
		{"without confirmation", "NO_LEARNED_ROUTE", "NO_QUALIFIED_STRATEGY", false},
		{"confirmed strategy blocked for endpoint", "LEARNED_STRATEGY_BLOCKED_FOR_ENDPOINT", "ENDPOINT_STRATEGY_NEGATIVE_TTL", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cur, q, p := youtubeFixture(t)
			q.Host = "rr1---sn-fixture.googlevideo.com"
			q.HintOnly = true
			r := c.browser.youtube
			key := youtubeScope(cur, q)
			endpoint := cdnEndpoint{q.Host, p.Destination.String()}
			id := youtubeLegacyOrder[0]
			until := time.Now().Add(youtubeLearnTTL)
			if tc.blocked {
				r.cache[key] = youtubeLearn{Stage: "LOCAL", Confirmed: true, Strategy: id, Until: until, Qualified: id}
				r.qualifications[youtubeQualification{key.Network, key.Profile, id, key.HintOnly}] = until
				if !r.endpointFailed(key, id, endpoint, "ORIGIN_SILENT", until.Add(-youtubeLearnTTL)) {
					t.Fatal("fixture did not set endpoint denial")
				}
			}
			wantStatus := "RELAY selected (" + tc.reason + ", local_admission=" + tc.admission + ")"
			var actions []flowpolicy.Action
			conn, plan, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
				actions = append(actions, plan.Policy.Action)
				if plan.Policy.Reason != wantStatus {
					t.Errorf("opener reason = %q, want %q", plan.Policy.Reason, wantStatus)
				}
				// Update the runtime after SELECTED. The snapshot must keep the
				// values used for this decision, including a missing cache row.
				r.mu.Lock()
				r.cache[key] = youtubeLearn{Stage: "DIRECT", Confirmed: true, Until: until}
				delete(r.endpointNegative, cdnEndpointKey{key, endpoint, id})
				r.mu.Unlock()
				a, b := net.Pipe()
				t.Cleanup(func() { b.Close() })
				return a, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if len(actions) != 1 || actions[0] != flowpolicy.RelayRequired || plan.Policy.Reason != wantStatus {
				t.Fatalf("actions = %v, returned policy = %+v", actions, plan.Policy)
			}
			record := snapshotConnectionEvidence(nativeBrowserRecord{Active: true, planReporter: conn.(browserproxy.PlanReporter)})
			if record.Policy.Action != flowpolicy.RelayRequired || record.Policy.Reason != wantStatus {
				t.Fatalf("connection status policy = %+v", record.Policy)
			}
			events := r.cdnDecisionSnapshot().Events
			if len(events) != 2 {
				t.Fatal(events)
			}
			selected, opened := events[0], events[1]
			if selected.Phase != "SELECTED" || selected.Stage != "RELAY" || selected.Reason != tc.reason || selected.Admission != tc.admission ||
				opened.Phase != "OPENED" || opened.Stage != "RELAY" || opened.Reason != "" || opened.ConnectionID != selected.ConnectionID {
				t.Fatal(events)
			}
			evidence := selected.Selection
			if evidence == nil || evidence.Scope != key || evidence.Trial == nil ||
				evidence.Trial.CheckedAt.Before(evidence.CheckedAt) || selected.At.Before(evidence.Trial.CheckedAt) {
				t.Fatalf("missing selection evidence: %+v", evidence)
			}
			if !tc.blocked {
				if evidence.Cache != nil || evidence.Endpoint != nil || evidence.Trial.Cache != nil || evidence.Trial.Endpoint != nil {
					t.Fatalf("no strategy should be available for an endpoint check: %+v", evidence)
				}
				return
			}
			for _, v := range []*cdnCacheEvidence{evidence.Cache, evidence.Trial.Cache} {
				if v == nil || v.Stage != "LOCAL" || !v.Confirmed || v.Strategy != id || !v.Until.Equal(until) || v.Qualified != id {
					t.Fatalf("wrong cache evidence: %+v", v)
				}
			}
			for _, v := range []*cdnEndpointCheck{evidence.Endpoint, evidence.Trial.Endpoint} {
				if v == nil || !v.Blocked || v.Strategy != id || !v.Until.Equal(until) {
					t.Fatalf("wrong endpoint evidence: %+v", v)
				}
			}
		})
	}
}

func TestCDNDecisionCapturesPeerProofBeforeCacheChanges(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		name := "eligible peer strategy"
		if blocked {
			name = "peer strategy blocked for endpoint"
		}
		t.Run(name, func(t *testing.T) {
			c, cur, q, p := youtubeFixture(t)
			c.Backend = &youtubeTransformFixture{}
			q.Host = "rr1---sn-target.googlevideo.com"
			r := c.browser.youtube
			key := youtubeScope(cur, q)
			proofKey := key
			proofKey.Domain = "googlevideo:sn-source"
			id := youtubeLegacyOrder[0]
			now := time.Now()
			r.mu.Lock()
			r.notePeerProofLocked(proofKey, id, now)
			r.mu.Unlock()
			if blocked && !r.endpointFailed(key, id, cdnEndpoint{q.Host, p.Destination.String()}, "ORIGIN_SILENT", now) {
				t.Fatal("fixture did not set endpoint denial")
			}
			conn, _, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
				want := flowpolicy.DirectPlus
				if blocked {
					want = flowpolicy.RelayRequired
				}
				if plan.Policy.Action != want {
					t.Errorf("opener action = %v, want %v", plan.Policy.Action, want)
				}
				r.mu.Lock()
				clear(r.peerProofs)
				r.mu.Unlock()
				a, b := net.Pipe()
				t.Cleanup(func() { b.Close() })
				return a, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			events := r.cdnDecisionSnapshot().Events
			if len(events) != 2 || events[0].Phase != "SELECTED" {
				t.Fatal(events)
			}
			wantReason := cdnPeerProvisionalReason
			if blocked {
				wantReason = "NO_LEARNED_ROUTE"
			}
			evidence := events[0].Selection
			if events[0].Reason != wantReason || evidence == nil || evidence.Scope != key || evidence.Cache != nil ||
				evidence.Peer == nil || evidence.Peer.Strategy != id || !evidence.Peer.Until.Equal(now.Add(youtubeLearnTTL)) ||
				evidence.Endpoint == nil || evidence.Endpoint.Strategy != id || evidence.Endpoint.Blocked != blocked {
				t.Fatalf("wrong SELECTED peer evidence: %+v", evidence)
			}
			if blocked && !evidence.Endpoint.Until.Equal(now.Add(youtubeLearnTTL)) {
				t.Fatalf("wrong peer endpoint TTL: %+v", evidence.Endpoint)
			}
		})
	}
}

func TestCDNDecisionReportsRelayAfterLocalOpenFailure(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.Backend = &youtubeTransformFixture{}
	r := c.browser.youtube
	r.confirmed(youtubeScope(cur, q), "LOCAL", youtubeLegacyOrder[0], time.Now())
	var actions []flowpolicy.Action
	conn, plan, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		actions = append(actions, plan.Policy.Action)
		if plan.Policy.Action == flowpolicy.DirectPlus {
			return nil, errors.New("fixture local open failed")
		}
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() })
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if len(actions) != 2 || actions[0] != flowpolicy.DirectPlus || actions[1] != flowpolicy.RelayRequired ||
		plan.Policy.Reason != "RELAY fallback (OPEN_FAILED)" {
		t.Fatalf("actions = %v, returned policy = %+v", actions, plan.Policy)
	}
	events := r.cdnDecisionSnapshot().Events
	if len(events) != 3 || events[0].Stage != "LOCAL" || events[1].Phase != "OPEN_FAILED" || events[2].Stage != "RELAY" ||
		events[2].Reason != "OPEN_FAILED" || events[2].ConnectionID != events[0].ConnectionID {
		t.Fatal(events)
	}
}

func TestCDNDecisionLinksLocalFirstFlightFailureToRelay(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.Backend = &youtubeTransformFixture{}
	q.Host = "rr1---sn-target.googlevideo.com"
	r := c.browser.youtube
	key := youtubeScope(cur, q)
	endpoint := cdnEndpoint{q.Host, p.Destination.String()}
	primary, alternate := youtubeLegacyOrder[0], youtubeLegacyOrder[1]
	now := time.Now()
	r.completeCDNQualification(key, primary, now)
	// Peer proof lets the first connection run as a regular LOCAL flow.
	// The target subgroup must earn its own confirmation from TLS data.
	peerKey := key
	peerKey.Domain = "googlevideo:sn-source"
	r.mu.Lock()
	r.qualifications[youtubeQualification{key.Network, key.Profile, alternate, key.HintOnly}] = now.Add(youtubeLearnTTL)
	r.notePeerProofLocked(peerKey, primary, now)
	r.mu.Unlock()

	body := bytes.Repeat([]byte("v"), 2*cdnStrongBytes)
	server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	usage := c.relayUsage()
	dialOrigin := func(ctx context.Context, request browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if err != nil || plan.Policy.Action != flowpolicy.RelayRequired {
			return conn, err
		}
		now := time.Now()
		videoID := usage.beginVideo(videoPerformance{Port: request.Port, Network: cur.network, Profile: cur.profile.ID,
			Domain: request.Host, Destination: plan.Destination.String(), Started: now})
		usage.videoOpened(videoID, now, now, nil)
		return &relayMeterConn{Conn: conn, usage: usage, videoID: videoID, profile: cur.profile.ID, domain: request.Host, release: func() {}}, nil
	}
	connect := func(open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) *youtubePlanConn {
		t.Helper()
		raw, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		conn, ok := raw.(*youtubePlanConn)
		if !ok {
			t.Fatalf("expected CDN ladder connection, got %T", raw)
		}
		return conn
	}
	transfer := func(conn net.Conn) {
		t.Helper()
		secure := tls.Client(conn, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
		if err := secure.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := secure.Handshake(); err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("GET", "https://"+q.Host+"/video-fixture", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Close = true
		if err := req.Write(secure); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(secure), req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK || n != int64(len(body)) {
			t.Fatalf("TLS/HTTP transfer: status=%d bytes=%d error=%v", resp.StatusCode, n, err)
		}
	}

	warm := connect(dialOrigin)
	transfer(warm)
	_ = warm.Close()
	warmEvents := r.cdnDecisionSnapshot().Events
	if len(warmEvents) != 2 || warmEvents[0].Phase != "SELECTED" || warmEvents[0].Reason != cdnPeerProvisionalReason ||
		warmEvents[0].Stage != "LOCAL" || warmEvents[0].Strategy != primary || warmEvents[0].TrialID != 0 {
		t.Fatalf("expected ordinary LOCAL from peer proof: %+v", warmEvents)
	}
	r.mu.Lock()
	confirmed := r.cache[key]
	r.mu.Unlock()
	if confirmed.Stage != "LOCAL" || !confirmed.Confirmed || confirmed.Strategy != primary || confirmed.VerifiedBytes <= 64*1024 {
		t.Fatalf("ordinary LOCAL did not confirm the subgroup: %+v", confirmed)
	}
	t.Logf("ordinary LOCAL confirmed %s with %d received bytes", confirmed.Strategy, confirmed.VerifiedBytes)

	beforeTimeout := len(warmEvents)
	firstWrite := make(chan time.Time, 1)
	openSilentPrimary := func(ctx context.Context, request browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action == flowpolicy.DirectPlus {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				if _, err := b.Read(make([]byte, 4096)); err != nil {
					return
				}
				firstWrite <- time.Now()
				_, _ = io.Copy(io.Discard, b)
			}()
			return a, nil
		}
		if plan.Policy.Action != flowpolicy.RelayRequired {
			t.Errorf("unexpected route: %v", plan.Policy.Action)
		}
		if plan.Policy.Reason != "RELAY fallback (ORIGIN_SILENT)" {
			t.Errorf("unexpected fallback status: %q", plan.Policy.Reason)
		}
		return dialOrigin(ctx, request, plan)
	}
	silent := connect(openSilentPrimary)
	transfer(silent)
	current := snapshotConnectionEvidence(nativeBrowserRecord{Active: true, planReporter: silent})
	if current.Policy.Action != flowpolicy.RelayRequired || current.Policy.Reason != "RELAY fallback (ORIGIN_SILENT)" {
		t.Fatalf("wrong status after LOCAL timeout: %+v", current.Policy)
	}
	_ = silent.Close()
	events := r.cdnDecisionSnapshot().Events[beforeTimeout:]
	if len(events) != 3 {
		t.Fatal(events)
	}
	selected, local, relay := events[0], events[1], events[2]
	if selected.Phase != "SELECTED" || selected.Stage != "LOCAL" || selected.Reason != "LEARNED_LOCAL" || selected.Admission != "NOT_NEEDED" ||
		local.Phase != "OPENED" || local.Stage != "LOCAL" || local.Strategy != primary ||
		relay.Phase != "OPENED" || relay.Stage != "RELAY" || relay.Reason != "ORIGIN_SILENT" ||
		relay.ConnectionID != selected.ConnectionID || local.ConnectionID != selected.ConnectionID ||
		relay.RecordID == local.RecordID || relay.Seq <= local.Seq || local.Selection != nil || relay.Selection != nil {
		t.Fatal(events)
	}
	for _, event := range events {
		if event.Host != endpoint.Host || event.Destination != endpoint.Address || event.TrialID != 0 {
			t.Fatalf("wrong endpoint or trial for the confirmed strategy: %+v", event)
		}
	}
	evidence := selected.Selection
	if evidence == nil || evidence.Cache == nil || evidence.Cache.Stage != "LOCAL" || !evidence.Cache.Confirmed ||
		evidence.Cache.Strategy != primary || !evidence.CheckedAt.Before(evidence.Cache.Until) ||
		evidence.Endpoint == nil || evidence.Endpoint.Blocked || evidence.Endpoint.Strategy != primary || evidence.Trial != nil {
		t.Fatalf("wrong LOCAL selection evidence: %+v", evidence)
	}
	select {
	case at := <-firstWrite:
		elapsed := relay.At.Sub(at)
		if elapsed < 850*time.Millisecond || elapsed > 1750*time.Millisecond {
			t.Fatalf("first client bytes to relay open = %s, expected 900 ms plus open/scheduling time", elapsed)
		}
		t.Logf("connection_id=%d: LOCAL to RELAY (ORIGIN_SILENT) in %s from first client bytes", relay.ConnectionID, elapsed)
	default:
		t.Fatal("LOCAL saw no client bytes")
	}

	now = time.Now()
	r.mu.Lock()
	denial := r.endpointNegative[cdnEndpointKey{key, endpoint, primary}]
	bothQualified := r.qualified(key, primary, now) && r.qualified(key, alternate, now)
	r.mu.Unlock()
	if denial.Reason != "ORIGIN_SILENT" || !now.Before(denial.Until) || !bothQualified {
		t.Fatalf("expected an active primary endpoint denial and two scoped proofs: denial=%+v bothQualified=%v", denial, bothQualified)
	}
	media := usage.mediaTrialSibling(cur.profile.ID, cur.network, q.Host, now)
	if !media.Eligible || media.MediaMatch != "EXACT_HOST" || media.MediaBytes <= cdnStrongBytes {
		t.Fatalf("fallback did not provide the required relay media: %+v", media)
	}

	next := connect(dialOrigin)
	events = r.cdnDecisionSnapshot().Events[beforeTimeout+3:]
	if len(events) != 2 {
		t.Fatal(events)
	}
	selected, opened := events[0], events[1]
	evidence = selected.Selection
	if evidence == nil || evidence.Scope != key || evidence.Trial == nil || evidence.Trial.Cache == nil {
		t.Fatalf("missing selection evidence for the next connection: %+v", evidence)
	}
	if selected.Phase != "SELECTED" || selected.Stage != "LOCAL" || selected.Reason != "LEARNED_STRATEGY_BLOCKED_FOR_ENDPOINT" ||
		selected.Admission != "ADMITTED" || selected.Strategy != alternate || selected.TrialID == 0 {
		t.Fatalf("next SELECTED %s %s: connection_id=%d trial_id=%d stage=%s reason=%s local_admission=%s strategy=%q qualified=%q, want LOCAL/ADMITTED %q",
			selected.Host, selected.Destination, selected.ConnectionID, selected.TrialID, selected.Stage, selected.Reason, selected.Admission, selected.Strategy, evidence.Trial.Cache.Qualified, alternate)
	}
	if evidence.Trial.Cache.Qualified != primary {
		t.Fatalf("wrong subgroup qualification at admission: %+v", evidence.Trial.Cache)
	}
	for _, check := range []*cdnEndpointCheck{evidence.Endpoint, evidence.Trial.Endpoint} {
		if check == nil || check.Strategy != primary || !check.Blocked || !check.Until.Equal(denial.Until) {
			t.Fatalf("primary strategy was not blocked at selection: %+v", check)
		}
	}
	if check := evidence.Trial.Alternate; check == nil || check.Strategy != alternate || check.Blocked {
		t.Fatalf("wrong alternate endpoint evidence: %+v", check)
	}
	if opened.Phase != "OPENED" || opened.Stage != "LOCAL" || opened.Strategy != alternate || selected.ConnectionID == 0 ||
		opened.ConnectionID != selected.ConnectionID || opened.ConnectionID == relay.ConnectionID ||
		opened.TrialID != selected.TrialID || opened.Seq <= selected.Seq ||
		selected.Host != endpoint.Host || opened.Host != endpoint.Host || selected.Destination != endpoint.Address || opened.Destination != endpoint.Address {
		t.Fatalf("alternate opening did not match its selection: selected=%+v opened=%+v", selected, opened)
	}
	transfer(next)
	if current := next.CurrentPlan(); current.Policy.Action != flowpolicy.DirectPlus {
		t.Fatalf("alternate did not carry the TLS/HTTP exchange over LOCAL: %+v", current.Policy)
	}
	t.Logf("%s %s: SELECTED LOCAL/ADMITTED -> OPENED LOCAL strategy=%s connection_id=%d trial_id=%d relay_rx=%d",
		opened.Host, opened.Destination, opened.Strategy, opened.ConnectionID, opened.TrialID, media.MediaBytes)
}

func TestCDNDecisionSnapshotFitsIPCWithSelectionEvidence(t *testing.T) {
	r := newYoutubeRuntime()
	at := time.Now()
	evidence := &cdnSelectionEvidence{
		CheckedAt: at,
		Scope:     youtubeKey{Network: strings.Repeat("n", 64), Profile: strings.Repeat("\x01", 128), Domain: "googlevideo:sn-fixture", Port: 443, HintOnly: true},
		Cache:     &cdnCacheEvidence{Stage: "LOCAL", Confirmed: true, Strategy: "catalog-1", Until: at, Qualified: "catalog-2"},
		Endpoint:  &cdnEndpointCheck{Strategy: "catalog-1", Blocked: true, Until: at},
		Trial:     &cdnTrialAdmissionEvidence{CheckedAt: at, Cache: &cdnCacheEvidence{Stage: "RELAY", Until: at, Qualified: "catalog-2"}, Endpoint: &cdnEndpointCheck{Strategy: "catalog-2"}},
	}
	for range cdnDecisionLimit + 5 {
		r.addCDNDecisionLocked(cdnDecisionEvent{Host: strings.Repeat("h", 237) + ".googlevideo.com", Destination: "74.125.111.131:443",
			Stage: "RELAY", Phase: "SELECTED", Reason: "LEARNED_STRATEGY_BLOCKED_FOR_ENDPOINT", Admission: "SCOPED_BULK_RELAY_NOT_OBSERVED", Selection: evidence})
	}
	s := r.cdnDecisionSnapshot()
	if len(s.Events) == 0 || s.Omitted <= 5 || s.Omitted+uint64(len(s.Events)) != s.LatestSeq || s.LatestSeq != cdnDecisionLimit+5 {
		t.Fatalf("unexpected tail: retained=%d omitted=%d latest=%d", len(s.Events), s.Omitted, s.LatestSeq)
	}
	for i, event := range s.Events {
		if event.Seq != s.Omitted+uint64(i)+1 || event.Selection != evidence {
			t.Fatalf("incomplete event: %+v", event)
		}
	}
	var frame bytes.Buffer
	if err := ipc.Write(&frame, ipc.Response{Version: ipc.Version, ID: strings.Repeat("\x01", 128), OK: true, Data: s}); err != nil {
		t.Fatal(err)
	}
}

func TestCDNDecisionSnapshotRetainsBoundedOrderedTail(t *testing.T) {
	r := newYoutubeRuntime()
	for range cdnDecisionLimit + 5 {
		r.addCDNDecisionLocked(cdnDecisionEvent{
			Host: strings.Repeat("h", 253), Destination: "[2001:db8:1234:1234:1234:1234:1234:1234]:443", Phase: "OPENED",
			Ingress: "PAC_NATIVE_UPSTREAM", Stage: "RELAY", Strategy: strings.Repeat("s", 96),
			Reason: "LOCAL_GUARD_OR_CAPACITY", Admission: "SCOPED_BULK_RELAY_NOT_OBSERVED",
		})
	}
	snapshot := r.cdnDecisionSnapshot()
	if snapshot.Omitted != 5 || len(snapshot.Events) != cdnDecisionLimit || snapshot.LatestSeq != cdnDecisionLimit+5 {
		t.Fatal(snapshot.Omitted, len(snapshot.Events), snapshot.LatestSeq)
	}
	for i, event := range snapshot.Events {
		if event.Seq != uint64(i+6) || event.ConnectionID != event.Seq {
			t.Fatal(event)
		}
	}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > ipc.MaxMessage-4096 {
		t.Fatal(len(data), err)
	}
}
