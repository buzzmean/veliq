package clientservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
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
	r := c.browser.youtube
	r.confirmed(youtubeScope(cur, q), "LOCAL", youtubeLegacyOrder[0], time.Now())
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	firstWrite := make(chan time.Time, 1)
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
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
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	raw, _, err := c.openYoutubeLadder(context.Background(), cur, q, p, open)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	secure := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	if err := secure.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	current := snapshotConnectionEvidence(nativeBrowserRecord{Active: true, planReporter: raw.(browserproxy.PlanReporter)})
	if current.Policy.Action != flowpolicy.RelayRequired || current.Policy.Reason != "RELAY fallback (ORIGIN_SILENT)" {
		t.Fatalf("wrong status after LOCAL timeout: %+v", current.Policy)
	}
	events := r.cdnDecisionSnapshot().Events
	if len(events) != 3 {
		t.Fatal(events)
	}
	selected, local, relay := events[0], events[1], events[2]
	if selected.Phase != "SELECTED" || selected.Stage != "LOCAL" || selected.Reason != "LEARNED_LOCAL" || selected.Admission != "NOT_NEEDED" ||
		local.Phase != "OPENED" || local.Stage != "LOCAL" || local.Strategy != youtubeLegacyOrder[0] ||
		relay.Phase != "OPENED" || relay.Stage != "RELAY" || relay.Reason != "ORIGIN_SILENT" ||
		relay.ConnectionID != selected.ConnectionID || local.ConnectionID != selected.ConnectionID ||
		relay.RecordID == local.RecordID || relay.Seq <= local.Seq || local.Selection != nil || relay.Selection != nil {
		t.Fatal(events)
	}
	evidence := selected.Selection
	if evidence == nil || evidence.Cache == nil || evidence.Cache.Stage != "LOCAL" || !evidence.Cache.Confirmed ||
		evidence.Cache.Strategy != youtubeLegacyOrder[0] || !evidence.CheckedAt.Before(evidence.Cache.Until) ||
		evidence.Endpoint == nil || evidence.Endpoint.Blocked || evidence.Endpoint.Strategy != youtubeLegacyOrder[0] || evidence.Trial != nil {
		t.Fatalf("wrong LOCAL selection evidence: %+v", evidence)
	}
	select {
	case at := <-firstWrite:
		elapsed := relay.At.Sub(at)
		if elapsed < 850*time.Millisecond || elapsed > 1750*time.Millisecond {
			t.Fatalf("first client bytes to relay open = %s, expected 900 ms plus open/scheduling time", elapsed)
		}
		t.Logf("first client bytes to relay open: %s", elapsed)
	default:
		t.Fatal("LOCAL saw no client bytes")
	}
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
