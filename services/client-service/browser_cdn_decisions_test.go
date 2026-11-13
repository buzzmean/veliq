package clientservice

import (
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
		selected.Host != q.Host || selected.Destination != p.Destination.String() || failed.ConnectionID != selected.ConnectionID ||
		failed.Phase != "OPEN_FAILED" || failed.Stage != "RELAY" || failed.Reason != "" || failed.RecordID == 0 {
		t.Fatal(events)
	}
}

func TestCDNDecisionLinksLocalFirstFlightFailureToRelay(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.Backend = &youtubeTransformFixture{}
	r := c.browser.youtube
	r.confirmed(youtubeScope(cur, q), "LOCAL", youtubeLegacyOrder[0], time.Now())
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action == flowpolicy.DirectPlus {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				_, _ = io.Copy(io.Discard, b)
			}()
			return a, nil
		}
		if plan.Policy.Action != flowpolicy.RelayRequired {
			t.Errorf("unexpected route: %v", plan.Policy.Action)
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
	events := r.cdnDecisionSnapshot().Events
	if len(events) != 3 {
		t.Fatal(events)
	}
	selected, local, relay := events[0], events[1], events[2]
	if selected.Phase != "SELECTED" || selected.Stage != "LOCAL" || selected.Reason != "LEARNED_LOCAL" || selected.Admission != "NOT_NEEDED" ||
		local.Phase != "OPENED" || local.Stage != "LOCAL" || local.Strategy != youtubeLegacyOrder[0] ||
		relay.Phase != "OPENED" || relay.Stage != "RELAY" || relay.Reason != "ORIGIN_SILENT" ||
		relay.ConnectionID != selected.ConnectionID || local.ConnectionID != selected.ConnectionID ||
		relay.RecordID == local.RecordID || relay.Seq <= local.Seq {
		t.Fatal(events)
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
