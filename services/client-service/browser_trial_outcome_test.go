package clientservice

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
)

type terminalTrialConn struct {
	net.Conn
	err    error
	closed atomic.Bool
}

func (c *terminalTrialConn) Read([]byte) (int, error) { return 0, c.err }
func (c *terminalTrialConn) Close() error {
	c.closed.Store(true)
	return nil
}

func trialMeterFixture(t *testing.T, trace localstrategy.TCPTrace, readErr error) (*youtubeMeter, *youtubeRuntime, youtubeKey, string) {
	t.Helper()
	r := newYoutubeRuntime()
	k := youtubeKey{"net", "chrome", "googlevideo:sn-fixture", 443, false}
	id := r.order[0]
	now := time.Now()
	r.qualifications[youtubeQualification{k.Network, k.Profile, id, false}] = now.Add(youtubeLearnTTL)
	r.completeCDNQualification(k, id, now)
	if _, ok := r.takeTrial(k, now, testSibling(true)); !ok {
		t.Fatal("not admitted")
	}
	r.records[1] = youtubeRecord{ID: 1, Stage: "LOCAL", Strategy: id, Active: true}
	r.trialRecord = 1
	m := &youtubeMeter{Conn: &terminalTrialConn{err: readErr}, r: r, id: 1, label: "local", key: k, stage: "LOCAL", strategy: id, trial: true, tx: 4458, rx: 6579, witnessChecked: true, applied: true, inspection: func() *localstrategy.Inspection { return &localstrategy.Inspection{TCPPackets: trace} }, transform: func() bool { return true }}
	hello := append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)
	m.wire.ObserveOrigin(hello)
	return m, r, k, id
}
func TestCDNClientFINThenRemoteFINIsNeutralAndReleasesOnlyItsOwnSlot(t *testing.T) {
	trace := localstrategy.TCPTrace{FirstClose: "CLIENT_PACKET", FirstCloseFlags: 17, ClientFIN: 1, RemoteFIN: 1}
	m, r, k, id := trialMeterFixture(t, trace, io.EOF)
	if _, e := m.Read(make([]byte, 100)); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	if m.failed || r.selection.TrialFailures != 0 || r.selection.FailedAfterReply != 0 || r.selection.TrialInconclusive != 1 || r.selection.TrialSuccesses != 0 || r.trialActive {
		t.Fatal("neutral poisoned trial", r.snapshot(), m.failed)
	}
	v := r.cache[k]
	if v.Qualified != id || v.Tried != 0 || v.Failures != 0 || v.Stage != "RELAY" {
		t.Fatal("neutral poisoned strategy or promoted LOCAL", v)
	}
	if v.TrialAfter.After(time.Now()) || v.NeutralShortStreak != 1 {
		t.Fatal("short neutral did not permit bounded next-flow retry")
	}
	other := k
	other.Domain = "googlevideo:sn-other"
	r.completeCDNQualification(other, id, time.Now())
	if _, ok := r.takeTrial(other, time.Now(), testSibling(true)); !ok {
		t.Fatal("different subgroup stuck")
	}
	m.Close() // Late wrapper Close must not release the newer peer trial.
	if !r.trialActive || r.trialKey != other || r.selection.TrialInconclusive != 1 {
		t.Fatal("late Close damaged another trial")
	}
}
func TestCDNRealFailuresAfterReplyStayFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		trace localstrategy.TCPTrace
		err   error
	}{
		{"remote reset", localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", FirstCloseFlags: 20, RemoteRST: 1}, syscall.ECONNRESET},
		{"remote eof", localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", FirstCloseFlags: 17, RemoteFIN: 1}, io.EOF},
		{"reset_with_retransmit", localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", FirstCloseFlags: 20, RemoteRST: 1, RemoteRetransmits: 1}, syscall.ECONNRESET},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, r, _, _ := trialMeterFixture(t, tc.trace, tc.err)
			if tc.name == "remote eof" {
				m.rx = 100 * 1024
			} // Large unconfirmed EOF is still a failure.
			m.Read(make([]byte, 50))
			m.Close()
			if !m.failed || r.selection.TrialFailures != 1 || r.selection.FailedAfterReply != 1 || r.selection.TrialInconclusive != 0 {
				t.Fatal(r.snapshot())
			}
		})
	}
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "CLIENT_PACKET", FirstCloseFlags: 17, ClientFIN: 1, RemoteFIN: 1}, io.EOF)
	m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	m.Read(make([]byte, 50))
	m.Close()
	if r.selection.TrialFailures != 1 || r.selection.FailedAfterReply != 1 {
		t.Fatal("timeout neutralized", r.snapshot())
	}
}
func TestCDNNeutralIsNotSustainedSuccessButHealthyClientCloseCounts(t *testing.T) {
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "CLIENT_PACKET", FirstCloseFlags: 17, ClientFIN: 1, RemoteFIN: 1}, io.EOF)
	m.rx = 70000
	m.healthy = true
	m.dataObserved = true
	m.Read(make([]byte, 50))
	m.Close()
	if r.selection.TrialSuccesses != 1 || r.selection.TrialInconclusive != 0 || r.selection.TrialFailures != 0 {
		t.Fatal(r.snapshot())
	}
}
func TestCDNAdmissionReasonsAndBackgroundRetryDoNotBlockRealFlows(t *testing.T) {
	r := newYoutubeRuntime()
	k := youtubeKey{"net", "chrome", "googlevideo:sn-admission", 443, false}
	now := time.Now()
	id := r.order[0]
	r.takeTrial(k, now, testSibling(true))
	if r.cache[k].TrialAdmission != "NO_QUALIFIED_STRATEGY" {
		t.Fatal(r.cache[k])
	}
	r.qualifications[youtubeQualification{k.Network, k.Profile, id, false}] = now.Add(youtubeLearnTTL)
	r.completeCDNQualification(k, id, now)
	r.takeTrial(k, now, testSibling(false))
	if r.cache[k].TrialAdmission != "RECENT_RELAY_SIBLING_NOT_OBSERVED" {
		t.Fatal(r.cache[k])
	}
	v := r.cache[k]
	v.Retry = now.Add(10 * time.Minute)
	r.cache[k] = v
	if _, ok := r.takeTrial(k, now, testSibling(true)); !ok {
		t.Fatal("background Retry wrongly gates trial", r.cache[k])
	}
	other := k
	other.Domain = "googlevideo:sn-b"
	r.takeTrial(other, now, testSibling(true))
	if r.cache[other].TrialAdmission != "GLOBAL_TRIAL_ACTIVE" {
		t.Fatal(r.cache[other])
	}
	r.finishTrial(k, id, false, true, now)
	r.takeTrial(k, now.Add(time.Minute), testSibling(true))
	if r.cache[k].TrialAdmission != "SUBGROUP_COOLDOWN" {
		t.Fatal(r.cache[k])
	}
}
func TestTrialTimingEvidenceDoesNotClaimDecryptedApplicationContent(t *testing.T) {
	now := time.Now()
	m := &youtubeMeter{firstClientWrite: now.Add(-time.Second), serverHelloAt: now.Add(-800 * time.Millisecond), lastReply: now.Add(-500 * time.Millisecond), rx: 8000, halfClosed: true}
	m.wire.ObserveClient([]byte{23, 3, 3, 0, 1, 0})
	m.wire.ObserveOrigin(append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...))
	tms := m.timingLocked(&localstrategy.Inspection{TCPPackets: localstrategy.TCPTrace{FirstCloseAt: now, LastRemoteBeforeCloseAt: now.Add(-400 * time.Millisecond)}}, now)
	if tms.ClientHelloToServerHelloMS != 200 || tms.ClientHelloToCloseMS != 1000 || tms.LastRXToCloseMS != 400 || tms.ReceivedAfterServerHello != 8000-47 || !tms.ClientApplicationRecord || !tms.HalfCloseRequested {
		t.Fatal(tms)
	}
}

func TestClientFINDoesNotPoisonWarmPublicLOCAL(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "CLIENT_PACKET", FirstCloseFlags: 17, ClientFIN: 1, RemoteFIN: 1}, io.EOF)
	r.finishTrialOutcome(k, id, "INCONCLUSIVE", true, time.Now(), m.rx)
	m.trial = false
	r.confirmed(k, "LOCAL", id, time.Now())
	m.Read(make([]byte, 100))
	m.Close()
	if r.cache[k].Stage != "LOCAL" || m.failed || r.stats[m.label].Failures != 0 {
		t.Fatal("client close poisoned warm LOCAL", r.cache[k], r.stats[m.label])
	}
}

func TestActualMidstreamTimeoutIsMarkedBeforeObserverClose(t *testing.T) {
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "CLIENT_PACKET", FirstCloseFlags: 17, ClientFIN: 1, RemoteFIN: 1}, io.EOF)
	a, b := net.Pipe()
	defer b.Close()
	m.Conn = a
	watched := browserproxy.WatchMidstream(m, 30*time.Millisecond, func() { m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED") })
	go func() {
		b.Write(append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...))
		b.Read(make([]byte, 32))
	}()
	watched.Read(make([]byte, 100))
	if _, e := watched.Write([]byte("encrypted request")); e != nil {
		t.Fatal(e)
	}
	if _, e := watched.Read(make([]byte, 100)); !errors.Is(e, browserproxy.ErrDirectMidstreamStall) {
		t.Fatal(e)
	}
	if r.selection.TrialFailures != 1 || r.selection.FailedAfterReply != 1 || r.selection.TrialInconclusive != 0 {
		t.Fatal("watchdog Close hid a real timeout", r.snapshot())
	}
}

func testSibling(eligible bool) relaySiblingEvidence {
	return relaySiblingEvidence{Eligible: eligible, AgeMS: 0, Reason: "UNIT_GUARD_SEAM"}
}
