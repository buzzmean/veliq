package windowsplatform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCaptureIngressShowsOwnerProfileAndNativeBoundary(t *testing.T) {
	id := ProcessIdentity{PID: 42, CreationTime: 17, Path: `C:\Apps\chrome.exe`}
	d := Decision{Deferred: true}
	d.Flow.ApplicationID = "chrome"
	for _, tc := range []struct {
		d         Decision
		syn, self bool
		want      string
	}{
		{Decision{}, true, false, "PROFILE_NOT_MATCHED"},
		{d, true, false, "DOMAIN_DEFERRED_SYN"},
		{d, false, false, "EXISTING_TCP_PINNED"},
		{d, true, true, "OWN_SERVICE_EXCLUDED"},
	} {
		if got := ingressDecision(id, tc.d, tc.syn, tc.self); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
	l := &captureIngress{}
	l.tcp.Add(10)
	l.nativeSYN.Add(1)
	l.accepted.Add(1)
	for i := 0; i < 30; i++ {
		l.record("TCP_SYN_CLASSIFY", id, testTuple(), d, "DOMAIN_DEFERRED_SYN", "TCP_OWNER_TABLE", "")
	}
	snap := l.snapshot(42)
	if snap.NativeDeferredSYN != 1 || snap.ReflectedAccepts != 1 || snap.TCPPackets != 10 || len(snap.Records) != 24 || snap.Lost != 6 {
		t.Fatal(snap)
	}
	r := snap.Records[0]
	if r.Profile != "chrome" || r.PID != 42 || r.Birth != 17 {
		t.Fatal(r)
	}
	if len(l.snapshot(43).Records) != 0 {
		t.Fatal("PID sample filter ignored")
	}
	raw, _ := json.Marshal(snap)
	if strings.Contains(string(raw), "command_line") {
		t.Fatal("unnecessary process content")
	}
	l.record("TCP_SYN_CLASSIFY", ProcessIdentity{PID: 0}, testTuple(), Decision{}, "PROCESS_IDENTITY_UNAVAILABLE", "TCP_OWNER_TABLE", "TCP_OWNER_NOT_FOUND")
	if got := l.snapshot(0).Records[23]; got.Error != "TCP_OWNER_NOT_FOUND" {
		t.Fatal(got)
	}
}
func TestCaptureIngressSkipsOrdinaryGameSamples(t *testing.T) {
	l := &captureIngress{}
	l.record("TCP_SYN_CLASSIFY", ProcessIdentity{PID: 42, Path: `C:\Games\cs2.exe`}, testTuple(), Decision{}, "DIRECT_DECISION", "TCP_OWNER_TABLE", "")
	if len(l.snapshot(0).Records) != 0 {
		t.Fatal("unrelated packet sampled")
	}
}
