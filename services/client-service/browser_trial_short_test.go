package clientservice

import (
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"io"
	"syscall"
	"testing"
	"time"
)

func TestSmallCDNEOFWithRetransmitsIsInconclusive(t *testing.T) {
	for _, rx := range []uint64{2717, 6579, 7109} {
		m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", FirstCloseFlags: 17, RemoteFIN: 1, ClientRetransmits: 1, RemoteRetransmits: 2}, io.EOF)
		m.host = "rr5---sn-u15hn5-5m.googlevideo.com"
		m.tx = 5791
		m.rx = rx
		m.firstClientWrite = time.Now().Add(-200 * time.Millisecond)
		m.serverHelloAt = time.Now().Add(-150 * time.Millisecond)
		m.lastReply = time.Now().Add(-10 * time.Millisecond)
		m.Read(make([]byte, 100))
		if r.trialActive {
			t.Fatal("EOF held the slot until Close")
		}
		m.Close()
		if m.failed || r.selection.TrialFailures != 0 || r.selection.FailedAfterReply != 0 || r.selection.RemoteSmallEOFInconclusive != 1 || r.trialActive {
			t.Fatalf("rx=%d small EOF poisoned strategy: failed=%v selection=%+v", rx, m.failed, r.selection)
		}
	}
}

func TestSmallCDNEOFNeverHidesResetAlertOrKnownTimeout(t *testing.T) {
	for _, kind := range []string{"rst", "alert", "timeout", "no-server-hello", "no-reply"} {
		t.Run(kind, func(t *testing.T) {
			trace := localstrategy.TCPTrace{RemoteFIN: 1, FirstClose: "REMOTE_PACKET", ClientRetransmits: 1}
			err := io.EOF
			if kind == "rst" {
				trace.RemoteRST = 1
				err = syscall.ECONNRESET
			}
			m, r, _, _ := trialMeterFixture(t, trace, err)
			m.rx = 7109
			switch kind {
			case "timeout":
				m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
			case "alert":
				m.wire = browserproxy.TLSWireObserver{}
				m.wire.ObserveOrigin([]byte{21, 3, 3, 0, 2, 2, 40})
			case "no-server-hello":
				m.wire = browserproxy.TLSWireObserver{}
			case "no-reply":
				m.rx = 0
				m.wire = browserproxy.TLSWireObserver{}
			}
			m.Read(make([]byte, 100))
			m.Close()
			if !m.failed || r.selection.TrialFailures != 1 || r.selection.RemoteSmallEOFInconclusive != 0 {
				t.Fatal(kind, r.snapshot())
			}
			if kind != "no-reply" && r.selection.FailedAfterReply != 1 {
				t.Fatal("real after-reply failure hidden")
			}
		})
	}
}
func TestShortTrialEvidenceSurvivesRecordEvictionAndKeepsExactHost(t *testing.T) {
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", RemoteFIN: 1, ClientRetransmits: 2}, io.EOF)
	m.host = "rr5---sn-test.googlevideo.com"
	m.firstClientWrite = time.Now().Add(-time.Second)
	delete(r.records, m.id)
	_, e := m.Read(make([]byte, 100))
	if !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	m.Close()
	if len(r.trials) != 1 || r.trials[0].Host != m.host || r.trials[0].TrialResult != "INCONCLUSIVE_SMALL_EOF" || r.trials[0].DataTrial || r.selection.DataTrials != 0 || r.trials[0].Timing.ClientHelloToCloseMS < 0 {
		t.Fatal(r.trials)
	}
}
func TestRecentRelaySiblingIsScopedAndExpires(t *testing.T) {
	u := &browserRelayUsage{}
	now := time.Now()
	host := "rr5---sn-test.googlevideo.com"
	group := youtubeSubgroup(host)
	id := u.beginVideo(videoPerformance{Port: 443, Profile: "chrome", Network: "net", Domain: host, Started: now})
	if u.trialSibling("chrome", "net", group, now).Eligible {
		t.Fatal("preconnect protected trial")
	}
	u.mu.Lock()
	u.videoIO(id, 5000, 128*1024, now)
	u.mu.Unlock()
	u.videoClosed(id, false)
	peer := u.trialSibling("chrome", "net", group, now.Add(15*time.Second))
	if !peer.Eligible || peer.Reason != "RECENT_SAME_SUBGROUP" || peer.AgeMS != 15000 {
		t.Fatal(peer)
	}
	other := u.trialSibling("chrome", "net", "googlevideo:sn-other", now.Add(time.Second))
	if !other.Eligible || other.Reason != "RECENT_CDN_CLASS" {
		t.Fatal(other)
	}
	for _, v := range []relaySiblingEvidence{u.trialSibling("edge", "net", group, now), u.trialSibling("chrome", "other", group, now), u.trialSibling("chrome", "", group, now), u.trialSibling("chrome", "net", group, now.Add(cdnSiblingTTL+time.Millisecond))} {
		if v.Eligible {
			t.Fatal("unscoped/stale sibling", v)
		}
	}
	// Ordinary Google/page traffic cannot protect a media trial.
	u2 := &browserRelayUsage{}
	id = u2.beginVideo(videoPerformance{Port: 443, Profile: "chrome", Network: "net", Domain: "www.youtube.com", Started: now})
	u2.mu.Lock()
	u2.videoIO(id, 10, 1024*1024, now)
	u2.mu.Unlock()
	if u2.trialSibling("chrome", "net", group, now).Eligible {
		t.Fatal("page protected video trial")
	}
}
func TestSiblingWaitsAreCountedWithoutBypassingCooldownOrMaxOne(t *testing.T) {
	_, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	r.finishTrialOutcome(k, id, "INCONCLUSIVE", false, time.Now(), 0)
	now := time.Now().Add(youtubeTrialCooldown + time.Second)
	peer := relaySiblingEvidence{AgeMS: 31000, Reason: "RELAY_ACTIVITY_EXPIRED"}
	for i := 0; i < 3; i++ {
		r.takeTrial(k, now, peer)
	}
	if r.cache[k].SiblingWaits != 3 || r.cache[k].Sibling.AgeMS != 31000 {
		t.Fatal(r.cache[k])
	}
	if _, ok := r.takeTrial(k, now, testSibling(true)); !ok {
		t.Fatal("recent proof not admitted")
	}
	if _, ok := r.takeTrial(k, now, testSibling(true)); ok {
		t.Fatal("max1 bypass")
	}
}

func TestBytesArrivingAfterFailureCannotRestoreLocalCache(t *testing.T) {
	m, r, k, _ := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	m.trial = false
	m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	m.postHelloWrite = true
	for i := 0; i < 8; i++ {
		m.wire.ObserveOrigin(append([]byte{23, 3, 3, 0x40, 0}, make([]byte, 16384)...))
	}
	m.account(0, 128*1024)
	if m.healthy || r.cache[k].Stage != "RELAY" {
		t.Fatal("failed LOCAL revived by late bytes", r.cache[k])
	}
}

func TestHandshakeBytesAloneAreNotADataTrialOrWeakSuccess(t *testing.T) {
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{RemoteFIN: 1}, io.EOF)
	m.healthy = true
	m.rx = 128 * 1024
	m.postHelloWrite = true
	m.Read(make([]byte, 100))
	m.Close()
	if r.selection.DataTrials != 0 || r.selection.TrialSuccesses != 0 || r.selection.TrialInconclusive != 1 {
		t.Fatal(r.selection)
	}
}

func TestNonHTTPSRelayMediaCannotProtectTLSTrial(t *testing.T) {
	u := &browserRelayUsage{}
	now := time.Now()
	id := u.beginVideo(videoPerformance{Port: 80, Profile: "chrome", Network: "net", Domain: "rr5---sn-test.googlevideo.com", Started: now})
	u.mu.Lock()
	u.videoIO(id, 1000, 1024*1024, now)
	u.mu.Unlock()
	if u.trialSibling("chrome", "net", "googlevideo:sn-test", now).Eligible {
		t.Fatal("HTTP80 protected HTTPS trial")
	}
}

func TestWarmLocalConfirmationKeepsSiblingWaitAudit(t *testing.T) {
	_, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	v := r.cache[k]
	v.SiblingWaits = 6
	v.TrialChecks = 7
	v.TrialDenials = 6
	v.Sibling = relaySiblingEvidence{AgeMS: 15000, Reason: "RECENT_CDN_CLASS"}
	r.cache[k] = v
	r.confirmed(k, "LOCAL", id, time.Now())
	if r.cache[k].SiblingWaits != 6 || r.cache[k].TrialDenials != 6 || r.cache[k].Sibling.AgeMS != 15000 {
		t.Fatal("warm traffic erased admission audit", r.cache[k])
	}
}

func TestLateKnownResetAfterSmallEOFRemainsVisible(t *testing.T) {
	m, r, k, _ := trialMeterFixture(t, localstrategy.TCPTrace{RemoteFIN: 1}, io.EOF)
	m.Read(make([]byte, 100))
	if r.selection.RemoteSmallEOFInconclusive != 1 {
		t.Fatal(r.selection)
	}
	m.inspection = func() *localstrategy.Inspection {
		return &localstrategy.Inspection{TCPPackets: localstrategy.TCPTrace{RemoteFIN: 1, RemoteRST: 1}}
	}
	m.Close()
	if !m.failed || r.selection.PostTrialFailures != 1 || r.selection.FailedAfterReply != 1 || r.cache[k].Qualified != "" || r.trials[0].TrialResult != "FAILED" {
		t.Fatal("late reset hidden", r.selection, r.trials)
	}
}

func TestSustainedTrialDoesNotHideHardReadError(t *testing.T) {
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{}, io.ErrUnexpectedEOF)
	m.healthy = true
	m.dataObserved = true
	m.rx = 200000
	m.Read(make([]byte, 100))
	m.Close()
	if !m.failed || r.selection.TrialFailures != 1 || r.selection.FailedAfterReply != 1 {
		t.Fatal("hard I/O hidden by old healthy marker", r.selection)
	}
}
