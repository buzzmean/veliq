package browserproxy

import (
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"strings"
	"testing"
	"time"
)

func TestFirstByteSeparatesGroupNetworkProfileModeAndFailures(t *testing.T) {
	var ledger firstByteLedger
	r := Record{Domain: "www.youtube.com", Owner: Owner{Profile: "chrome"}, Plan: Plan{Network: "net-a"}, EvidenceSource: "PAC_CONNECT", FirstByteMode: "DIRECT_FIRST"}
	ledger.observe(r, 2100*time.Millisecond)
	r.Domain = "rr1---sn-any.googlevideo.com"
	r.FirstByteMode = "RELAY_FIRST"
	ledger.observe(r, 55*time.Millisecond)
	ledger.observe(r, 65*time.Millisecond)
	ledger.observe(r, -1) // Failure is not a zero-ms success.
	r.Plan.Network = "net-b"
	ledger.observe(r, 99*time.Millisecond)
	r.Owner.Profile = "edge"
	ledger.observe(r, 100*time.Millisecond)
	rows, lost := ledger.snapshot()
	if len(rows) != 4 || lost != 0 {
		t.Fatal(rows, lost)
	}
	for _, m := range rows {
		if m.Group != "youtube-media" {
			t.Fatal(m)
		}
		if m.Network == "net-a" && m.Mode == "RELAY_FIRST" && (m.Replies != 2 || m.NoReply != 1 || m.TotalMS != 120 || m.MinMS != 55 || m.MaxMS != 65) {
			t.Fatal(m)
		}
	}
	r.Port = 80
	ledger.observe(r, 8*time.Millisecond)
	if scoped, _ := ledger.snapshot(); len(scoped) != 5 {
		t.Fatal("different ports mixed", scoped)
	}
	r.FirstByteMode = "RELAY_FIRST"
	r.Plan.DirectAttempts = 1
	r.Plan.Policy.Action = flowpolicy.RelayRequired
	if firstByteMode(r.Plan) != "DIRECT_FIRST" {
		t.Fatal("retry incorrectly called relay-first")
	}
}
func TestFirstByteEvidenceIsBoundedAndUnknownSamplesAreNotInvented(t *testing.T) {
	var ledger firstByteLedger
	rows, lost := ledger.snapshot()
	if len(rows) != 0 || lost != 0 {
		t.Fatal(rows, lost)
	}
	for i := 0; i < 140; i++ {
		ledger.observe(Record{Domain: fmt.Sprintf("site-%d.example", i)}, -1)
	}
	rows, lost = ledger.snapshot()
	if len(rows) != 128 || lost != 12 {
		t.Fatal(len(rows), lost)
	}
	for _, m := range rows {
		if m.Replies != 0 || m.NoReply != 1 || m.MinMS != -1 || m.LastMS != -1 {
			t.Fatal("failure fabricated latency", m)
		}
	}
}

func TestFirstByteReportOwnBoundDoesNotTruncateRoutingLedger(t *testing.T) {
	s := &Server{records: map[uint64]Record{1: {ID: 1, Domain: "www.youtube.com"}}}
	for i := 0; i < 128; i++ {
		r := Record{Plan: Plan{Network: strings.Repeat("a", 64)}, Domain: fmt.Sprintf("long-%03d.%s", i, strings.Repeat("x", 220)), Owner: Owner{Profile: fmt.Sprintf("profile-%03d", i)}, EvidenceSource: "PAC_CONNECT", FirstByteMode: "DIRECT_FIRST"}
		s.firstBytes.observe(r, time.Second)
	}
	report := s.FirstBytes()
	raw, err := json.Marshal(report)
	if err != nil || len(raw) >= 57000 || !report.Truncated || report.Omitted == 0 {
		t.Fatal("report not independently bounded", len(raw), report.Omitted, err)
	}
	if len(s.records) != 1 || s.lost != 0 {
		t.Fatal("metrics touched routing ledger")
	}
}

func TestFirstByteKnownGroupsRemainSeparateFromYouTubeAndOrdinary(t *testing.T) {
	var l firstByteLedger
	for _, host := range []string{"KWS2.Web.Telegram.Org.", "t.me", "claude.ai", "api.anthropic.com", "bridge.claudeusercontent.com", "claude.com", "r.googlevideo.com", "claude.ai.example"} {
		l.observe(Record{Domain: host, FirstByteMode: "RELAY_FIRST"}, time.Millisecond)
	}
	rows, _ := l.snapshot()
	counts := map[string]uint64{}
	for _, row := range rows {
		counts[row.Group] += row.Replies
	}
	if counts["telegram"] != 2 || counts["anthropic"] != 4 || counts["youtube-media"] != 1 || counts["claude.ai.example"] != 1 {
		t.Fatal(counts)
	}
	if flowpolicy.DirectTimeoutHost("claude.ai") != "claude.ai" || flowpolicy.DirectTimeoutHost("web.telegram.org") != "web.telegram.org" {
		t.Fatal("known rules polluted YouTube learned cache")
	}
}
