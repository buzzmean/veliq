package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/security"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func clubSocketFixture(peer string, pid uint32, birth uint64) wp.ClubLinkSocket {
	protocol := "TCP4"
	p := netip.MustParseAddrPort(peer)
	if p.Addr().Is6() {
		protocol = "TCP6"
	}
	return wp.ClubLinkSocket{Peer: p, Protocol: protocol,
		Identity: wp.ProcessIdentity{PID: pid, CreationTime: birth, Path: `C:\LanGame\LanGameService.exe`}}
}

func clubDiagnosticFixture(d *persistentDiagnostics, at time.Time) clubhealth.Diagnostic {
	e := d.event("CLUB_LINK", "PASSIVE_TCP_TABLE", "failed", "CONNECTION_LOST")
	e.At, e.PID, e.Birth, e.App, e.ProcessVerified = at, 24, 100, "langameservice.exe", true
	e.Incident = strings.Repeat("c", 32)
	e.ClubLink = clubhealth.ClubLink{Kind: "LANGAME", LinkID: e.Incident, PeerID: strings.Repeat("d", 32), Protocol: "TCP4",
		Event: e.Code, Previous: "ESTABLISHED", Current: "ABSENT", LastEstablishedAt: at.Add(-4 * time.Second)}
	return e
}

func TestClubLinkProducerAlwaysPreservesDownlevelEnvelope(t *testing.T) {
	d := &persistentDiagnostics{base: clubhealth.Diagnostic{PC: "PC13", Version: "0.3.792", Source: "095c8ac8", Session: strings.Repeat("b", 32), ServicePID: 10}}
	at := time.Now().UTC()
	for _, protocol := range []string{"TCP4", "TCP6"} {
		for _, event := range []string{"CONNECTION_LOST", "CONNECTION_RESTORED"} {
			link := clubDiagnosticFixture(d, at).ClubLink
			link.Protocol = protocol
			if event == "CONNECTION_RESTORED" {
				link.Event, link.Previous, link.Current, link.LastEstablishedAt = event, "ABSENT", "ESTABLISHED", at
			}
			e, ok := d.clubLinkEvent(clubLinkFact{link: link, owner: clubSocketFixture("10.2.3.4:9917", 24, 100).Identity}, at)
			if !ok || !e.Valid(at) || !strings.HasPrefix(e.Operation, "CL1_") || e.ClubLink != link {
				t.Fatal("producer omitted a valid typed/envelope pair")
			}
			e.ClubLink = clubhealth.ClubLink{}
			effective, ok := e.EffectiveClubLink()
			if !ok || effective != link {
				t.Fatal("old journal would lose producer evidence")
			}
		}
	}
}

func TestClubLinkPeerLossNeedsTwoCompleteSamplesAndPositiveRestoration(t *testing.T) {
	at := time.Now().UTC()
	first := clubSocketFixture("10.2.3.4:9917", 24, 100)
	other := clubSocketFixture("10.2.3.5:3456", 28, 101)
	var tracker clubLinkTracker
	observe := func(seconds int, sockets ...wp.ClubLinkSocket) []clubLinkFact {
		return tracker.observe(wp.ClubLinkSnapshot{Sockets: sockets}, nil, at.Add(time.Duration(seconds)*time.Second))
	}
	if len(observe(0)) != 0 || len(observe(2, first, first, other)) != 0 {
		t.Fatal("startup empty/baseline reported as an outage")
	}
	// A socket generation changes, but another established socket to the same
	// peer is already present: this is a replacement, not a disconnection.
	replacement := first
	replacement.Identity.PID, replacement.Identity.CreationTime = 32, 102
	if len(observe(4, replacement, other)) != 0 || len(observe(6, other)) != 0 {
		t.Fatal("replacement/one missing sample produced a loss")
	}
	lost := observe(8, other)
	if len(lost) != 1 || lost[0].link.Event != "CONNECTION_LOST" || lost[0].owner != replacement.Identity ||
		!lost[0].link.LastEstablishedAt.Equal(at.Add(4*time.Second)) {
		t.Fatal("exact last observed owner/baseline missing", lost)
	}
	if len(observe(10, other)) != 0 {
		t.Fatal("same sustained absence generated another incident")
	}
	restored := observe(12, first, other)
	if len(restored) != 1 || restored[0].link.Event != "CONNECTION_RESTORED" ||
		restored[0].link.LinkID != lost[0].link.LinkID || restored[0].link.PeerID != lost[0].link.PeerID ||
		!restored[0].link.LastEstablishedAt.Equal(at.Add(12*time.Second)) || restored[0].owner != first.Identity {
		t.Fatal("positive TCP observation did not retain exact episode", restored)
	}
	if len(observe(14, first, other)) != 0 || len(observe(16, other)) != 0 {
		t.Fatal("stable connection/first missing sample duplicated event")
	}
	next := observe(18, other)
	if len(next) != 1 || next[0].link.LinkID == lost[0].link.LinkID || next[0].link.PeerID != lost[0].link.PeerID {
		t.Fatal("new outage reused old incident ID", next)
	}
}

func TestClubLinkUnknownTablesOwnersAndTimeGapsNeverProveLoss(t *testing.T) {
	for _, kind := range []string{"native_error", "unknown_owner", "time_gap", "unverified", "bound"} {
		t.Run(kind, func(t *testing.T) {
			at := time.Now().UTC()
			socket := clubSocketFixture("[fd01::2]:9917", 24, 100)
			var tracker clubLinkTracker
			tracker.observe(wp.ClubLinkSnapshot{Sockets: []wp.ClubLinkSocket{socket}}, nil, at)
			tracker.observe(wp.ClubLinkSnapshot{}, nil, at.Add(2*time.Second))
			var events []clubLinkFact
			switch kind {
			case "native_error":
				events = tracker.observe(wp.ClubLinkSnapshot{}, errors.New("partial TCP6 table"), at.Add(4*time.Second))
			case "unknown_owner":
				events = tracker.observe(wp.ClubLinkSnapshot{UnknownPeers: []netip.AddrPort{socket.Peer}}, nil, at.Add(4*time.Second))
			case "time_gap":
				events = tracker.observe(wp.ClubLinkSnapshot{}, nil, at.Add(12*time.Second))
			case "unverified":
				socket.Identity.Path = `C:\Other\chrome.exe`
				events = tracker.observe(wp.ClubLinkSnapshot{Sockets: []wp.ClubLinkSocket{socket}}, nil, at.Add(4*time.Second))
			case "bound":
				rows := make([]wp.ClubLinkSocket, clubLinkPeers*16+1)
				events = tracker.observe(wp.ClubLinkSnapshot{Sockets: rows}, nil, at.Add(4*time.Second))
			}
			if len(events) != 0 {
				t.Fatal("unavailable/incomplete observation created loss", events)
			}
			if len(tracker.observe(wp.ClubLinkSnapshot{}, nil, at.Add(20*time.Second))) != 0 {
				t.Fatal("missing confirmation crossed an unobserved interval")
			}
		})
	}
}

func TestClubLinkNeverSeedsPublicOrUnverifiedBaseline(t *testing.T) {
	for _, socket := range []wp.ClubLinkSocket{
		clubSocketFixture("203.0.113.2:9917", 24, 100),
		clubSocketFixture("10.2.3.4:9917", 24, 0),
		clubSocketFixture("10.2.3.4:9917", 0, 100),
	} {
		at := time.Now().UTC()
		var tracker clubLinkTracker
		tracker.observe(wp.ClubLinkSnapshot{Sockets: []wp.ClubLinkSocket{socket}}, nil, at)
		tracker.observe(wp.ClubLinkSnapshot{}, nil, at.Add(2*time.Second))
		if len(tracker.observe(wp.ClubLinkSnapshot{}, nil, at.Add(4*time.Second))) != 0 {
			t.Fatal("untrusted/public baseline produced incident")
		}
	}
}

func TestClubLinkImmediateFlushWakesOnlyAfterDurableWrite(t *testing.T) {
	d := diagnosticRuntimeFixture()
	d.clubInputs, d.uploadWake, d.done = make(chan diagnosticInput, 2), make(chan struct{}, 1), make(chan struct{})
	entered, release := make(chan []byte, 1), make(chan struct{})
	d.write = func(raw []byte) error {
		entered <- append([]byte(nil), raw...)
		<-release
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); close(release); <-d.done }()
	go d.run(ctx, t.TempDir()+"/journal.json", "device")
	e := clubDiagnosticFixture(d, time.Now().UTC())
	d.clubInputs <- diagnosticInput{event: e}
	select {
	case raw := <-entered:
		var journal clubhealth.Journal
		if json.Unmarshal(raw, &journal) != nil || len(journal.Rows) != 1 || journal.Rows[0].Event != e {
			t.Fatal("urgent flush did not contain the observed fact")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("club event waited for the ordinary 10s journal timer")
	}
	select {
	case <-d.uploadWake:
		t.Fatal("network upload woke before durable commit")
	default:
	}
	release <- struct{}{}
	select {
	case <-d.uploadWake:
	case <-time.After(2 * time.Second):
		t.Fatal("durable club fact did not wake uploader")
	}
}

func TestClubLinkWakeUsesExistingAuthenticatedUpload(t *testing.T) {
	d := diagnosticRuntimeFixture()
	d.clubInputs, d.uploadWake, d.done = make(chan diagnosticInput, 2), make(chan struct{}, 1), make(chan struct{})
	d.write = func([]byte) error { return nil }
	received := make(chan clubhealth.Batch, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q clubhealth.PersistentRequest
		if json.NewDecoder(r.Body).Decode(&q) != nil || q.Batch.Validate(time.Now()) != nil || q.Proof.RelayID != q.Batch.Audience() {
			t.Error("invalid signed diagnostic upload")
			w.WriteHeader(400)
			return
		}
		received <- q.Batch
		_ = json.NewEncoder(w).Encode(clubhealth.Receipt{Protocol: 1, Committed: true, Digest: q.Batch.Audience()})
	}))
	defer server.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	d.cp.Store(&controlclient.Client{BaseURL: server.URL, DeviceID: "device", DeviceKey: key, AllowHTTPDevelopment: true})
	ctx, cancel := context.WithCancel(context.Background())
	uploadDone := make(chan struct{})
	defer func() { cancel(); <-d.done; <-uploadDone }()
	go d.run(ctx, t.TempDir()+"/journal.json", "device")
	go func() { defer close(uploadDone); d.upload(ctx) }()
	e := clubDiagnosticFixture(d, time.Now().UTC())
	d.clubInputs <- diagnosticInput{event: e}
	select {
	case b := <-received:
		if len(b.Events) == 0 || b.Events[0] != e {
			t.Fatal("uploader lost club metadata")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("urgent diagnostic waited for ordinary 30s upload heartbeat")
	}
}

func TestClubLinkBatchSkipsLargeOldBacklogWithoutStarvingLifecycle(t *testing.T) {
	d := diagnosticRuntimeFixture()
	now := time.Now().UTC()
	j := clubhealth.Journal{Format: 1}
	for i := range 100 {
		e := d.event("SERVICE", "FIXTURE", "failed", "ERROR")
		e.ID = fmt.Sprintf("%032x", i+1)
		j.Rows = append(j.Rows, clubhealth.JournalRow{Event: e})
	}
	for range 10 {
		e := clubDiagnosticFixture(d, now)
		e.ID, _ = security.NewID()
		j.Rows = append(j.Rows, clubhealth.JournalRow{Event: e})
	}
	b := clubLinkDiagnosticBatch(j)
	club, lifecycle := 0, 0
	for _, e := range b.Events {
		if e.ClubLink.IsZero() {
			lifecycle++
		} else {
			club++
		}
	}
	if len(b.Events) != clubhealth.MaxEvents || club != clubhealth.MaxEvents/2 || lifecycle != clubhealth.MaxEvents/2 || b.Events[0].ClubLink.IsZero() {
		t.Fatal("urgent metadata buried in backlog or starved other diagnostics", club, lifecycle)
	}
	// Lifecycle must still receive its reserved room if the journal begins with
	// a large outage burst rather than with the old lifecycle records above.
	j.Rows = append(append([]clubhealth.JournalRow(nil), j.Rows[100:]...), j.Rows[:100]...)
	lifecycle = 0
	for _, e := range clubLinkDiagnosticBatch(j).Events {
		if e.ClubLink.IsZero() {
			lifecycle++
		}
	}
	if lifecycle != clubhealth.MaxEvents/2 {
		t.Fatal("outage burst starved lifecycle", lifecycle)
	}
}

func TestClubLinkBatchKeepsDownlevelFactAheadOfOrdinaryBacklog(t *testing.T) {
	d := diagnosticRuntimeFixture()
	now := time.Now().UTC()
	j := clubhealth.Journal{Format: 1}
	for i := range 100 {
		e := d.event("SERVICE", "FIXTURE", "failed", "ERROR")
		e.ID = fmt.Sprintf("%032x", i+1)
		j.Rows = append(j.Rows, clubhealth.JournalRow{Event: e})
	}
	e, ok := clubDiagnosticFixture(d, now).WithClubLinkShadow()
	if !ok {
		t.Fatal("fixture")
	}
	e.ClubLink = clubhealth.ClubLink{} // Exact762 acceptance separately proves this codec result.
	j.History = []clubhealth.JournalRow{{Event: e}}
	b := clubLinkDiagnosticBatch(j)
	if len(b.Events) != clubhealth.MaxEvents || b.Events[0] != e || b.Events[1].Component != "SERVICE" {
		t.Fatal("downlevel pending fact lost urgency or starved ordinary diagnostics")
	}
}

func TestClubLinkWakeCoalescesAndPreservesRetryBackoff(t *testing.T) {
	d := diagnosticRuntimeFixture()
	d.uploadWake = make(chan struct{}, 1)
	for range 1000 {
		d.wakeDiagnosticUpload()
	}
	if len(d.uploadWake) != 1 {
		t.Fatal("wake queue is not bounded/coalesced")
	}
	start := time.Now()
	if !waitDiagnosticUpload(context.Background(), 80*time.Millisecond, d.uploadWake, start.Add(time.Minute)) || time.Since(start) < 60*time.Millisecond {
		t.Fatal("urgent traffic bypassed server failure backoff")
	}
	d.wakeDiagnosticUpload()
	if !waitDiagnosticUpload(context.Background(), time.Minute, d.uploadWake, time.Time{}) {
		t.Fatal("normal idle upload not woken")
	}
}
