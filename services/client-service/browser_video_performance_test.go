package clientservice

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestVideoPerformanceSeparatesAdmissionOpenFirstByteAndRate(t *testing.T) {
	u := &browserRelayUsage{}
	start := time.Now().Add(-5 * time.Second)
	id := u.beginVideo(videoPerformance{Started: start, Profile: "chrome", Domain: "r.googlevideo.com", Ingress: "NATIVE_TCP"})
	u.videoOpened(id, start.Add(20*time.Millisecond), start.Add(100*time.Millisecond), nil)
	u.accountIO("chrome", "r.googlevideo.com", 100, 0, start.Add(150*time.Millisecond), id)
	u.accountIO("chrome", "r.googlevideo.com", 0, 1000000, start.Add(time.Second), id)
	u.accountIO("chrome", "r.googlevideo.com", 0, 1000000, start.Add(2*time.Second), id)
	u.mu.Lock()
	rows := u.videoSnapshot(start.Add(4 * time.Second))
	u.mu.Unlock()
	v := rows[0]
	if v.AdmissionMS != 20 || v.OpenMS != 80 || v.FirstByteMS != 1000 || v.WriteToFirstMS != 850 || v.AverageMbps != 4 || v.ReceiveSpanMbps != 8 || v.MaxReadGapMS != 1000 || v.Received != 2000000 || v.Sent != 100 {
		t.Fatalf("%+v", v)
	}
	u.videoClosed(id, false)
	a := u.snapshot().VideoConnections[0]
	time.Sleep(time.Millisecond)
	b := u.snapshot().VideoConnections[0]
	if a.AverageMbps != b.AverageMbps || a.State != "CLOSED" {
		t.Fatal("closed rate changed", a, b)
	}
}
func TestVideoPerformanceNoReplyBoundAndSnapshotAreHonest(t *testing.T) {
	u := &browserRelayUsage{}
	now := time.Now()
	for i := 0; i < videoPerformanceCapacity+10; i++ {
		id := u.beginVideo(videoPerformance{Started: now, Domain: fmt.Sprint(i)})
		u.videoClosed(id, false)
	}
	if len(u.videos) != videoPerformanceCapacity {
		t.Fatal(len(u.videos))
	}
	s := u.snapshot()
	if len(s.VideoConnections) != 24 || s.VideoOmitted != 114 {
		t.Fatal(s.VideoOmitted)
	}
	for _, r := range s.VideoConnections {
		if r.FirstByteMS != -1 || r.AverageMbps != -1 || r.ReceiveSpanMbps != -1 {
			t.Fatal("no reply fabricated", r)
		}
	}
	u = &browserRelayUsage{}
	for i := 0; i < videoPerformanceCapacity; i++ {
		if u.beginVideo(videoPerformance{Started: now}) == 0 {
			t.Fatal("early cap")
		}
	}
	if u.beginVideo(videoPerformance{Started: now}) != 0 || u.videoLost != 1 {
		t.Fatal("unbounded active ledger")
	}
}
func TestVideoPerformanceMeterActualIOAndClose(t *testing.T) {
	u := &browserRelayUsage{}
	start := time.Now()
	id := u.beginVideo(videoPerformance{Started: start})
	u.videoOpened(id, start, start, nil)
	a, b := net.Pipe()
	defer b.Close()
	c := &relayMeterConn{Conn: a, usage: u, videoID: id, release: func() {}}
	go func() { defer b.Close(); buf := make([]byte, 3); b.Read(buf); b.Write([]byte("reply")) }()
	if _, e := c.Write([]byte("ask")); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 8)
	if n, e := c.Read(buf); n != 5 || e != nil {
		t.Fatal(n, e)
	}
	c.Close()
	c.Close()
	v := u.snapshot().VideoConnections[0]
	if v.Received != 5 || v.Sent != 3 || v.FirstByteMS < 0 || v.Closed.IsZero() {
		t.Fatal(v)
	}
}

func TestVideoPerformanceKeepsLongLivedVideoVisibleOverClosedPreconnects(t *testing.T) {
	u := &browserRelayUsage{}
	now := time.Now()
	active := u.beginVideo(videoPerformance{Started: now})
	for i := 0; i < 50; i++ {
		id := u.beginVideo(videoPerformance{Started: now})
		u.videoClosed(id, false)
	}
	rows := u.snapshot().VideoConnections
	if len(rows) != 24 || rows[0].ID != active || !rows[0].Closed.IsZero() {
		t.Fatal("active video hidden by closed preconnects", rows)
	}
}

func TestVideoPerformanceCannotOverflowPACStatusIPC(t *testing.T) {
	v := browserStatusView{}
	profile := strings.Repeat("p", 128)
	domain := strings.Repeat("a", 250) + ".io"
	now := time.Now()
	for i := 0; i < 24; i++ {
		v.RelayUsage.VideoConnections = append(v.RelayUsage.VideoConnections, videoPerformance{ID: uint64(i), Profile: profile, Domain: domain, Destination: "173.194.151.68:443", Ingress: "NATIVE_TCP", Started: now, Opened: now, FirstRead: now, LastRead: now, FirstWrite: now})
	}
	for i := 0; i < 64; i++ {
		v.RelayUsage.ActiveOrigins = append(v.RelayUsage.ActiveOrigins, relayActiveOrigin{Profile: profile, Domain: domain, Active: 1})
		v.RelayUsage.Minutes = append(v.RelayUsage.Minutes, relayMinute{Profile: profile, Domain: domain, Minute: now})
	}
	v.bound()
	raw, e := json.Marshal(v)
	if e != nil || len(raw) >= 57000 || !v.Truncated || v.RelayUsage.VideoOmitted == 0 {
		t.Fatal("unbounded combined PAC status", len(raw), e, v.RelayUsage.VideoOmitted)
	}
}
