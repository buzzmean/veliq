package clientservice

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/localstrategy"
)

func TestCDNIdleShortReplyReleasesOnlyItsOwnTrialSlot(t *testing.T) {
	trace := localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", FirstCloseFlags: 17, RemoteFIN: 1}
	m, r, k, id := trialMeterFixture(t, trace, os.ErrDeadlineExceeded)
	conn := m.Conn.(*terminalTrialConn)
	m.trialID = r.trialID
	now := time.Now()
	m.lastReply = now.Add(-cdnBurstQuiet)
	m.lastClientWrite = now.Add(-time.Second)
	m.releaseIdleShortTrial(now)
	if !r.trialActive {
		t.Fatal("released a trial with an unanswered write")
	}
	m.lastClientWrite = m.lastReply
	m.releaseIdleShortTrial(now.Add(-time.Millisecond))
	if !r.trialActive {
		t.Fatal("released before the quiet period elapsed")
	}

	if _, err := m.Read(make([]byte, 100)); err != os.ErrDeadlineExceeded {
		t.Fatal(err)
	}
	s := r.snapshot().Selection
	if s.ActiveTrial || s.TrialInconclusive != 1 || s.TrialFailures != 0 || s.TrialSuccesses != 0 ||
		s.SlotReleaseReason != cdnShortReplyIdle || conn.closed.Load() || r.cache[k].Stage != "RELAY" {
		t.Fatalf("idle short reply: closed=%v selection=%+v", conn.closed.Load(), s)
	}
	if len(r.trials) != 1 || !r.trials[0].Active || r.trials[0].SlotActive || r.trials[0].TrialID != m.trialID {
		t.Fatal("trial evidence lost the open connection or slot identity", r.trials)
	}
	_, nextID, ok := r.takeEndpointTrial(k, time.Now(), testSibling(true), cdnEndpoint{})
	if !ok || nextID == m.trialID {
		t.Fatal("next eligible flow did not receive a new slot")
	}

	conn.err = io.EOF
	m.Read(make([]byte, 100))
	m.Close()
	if !r.trialActive || r.trialID != nextID || r.trialStrategy != id || r.selection.TrialInconclusive != 1 ||
		len(r.trials) != 1 || r.trials[0].TrialResult != "INCONCLUSIVE_SMALL_EOF" || r.trials[0].SlotReleaseReason != cdnShortReplyIdle {
		t.Fatal("late EOF changed the newer trial or overwrote the earlier release", r.snapshot(), r.trials)
	}
}

func TestCDNCallbackSmallEOFReleasesSlotBeforeReadOrClose(t *testing.T) {
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", FirstCloseFlags: 17, RemoteFIN: 1}, io.EOF)
	m.rx = 5568
	m.tx = 4605
	m.failure("REMOTE_EOF_AFTER_REPLY") // FirstFlight callback, not meter.Read.
	s := r.snapshot()
	if s.Selection.ActiveTrial || s.Selection.TrialInconclusive != 1 || s.Selection.RemoteSmallEOFInconclusive != 1 {
		t.Fatalf("callback held neutral slot: %+v", s.Selection)
	}
	m.Close()
	if r.selection.TrialInconclusive != 1 {
		t.Fatal("Close finalized twice")
	}
}

func TestCDNNeutralShortRetriesBoundedAndRequireSiblingEveryTime(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", RemoteFIN: 1}, io.EOF)
	now := time.Now()
	for attempt := 1; attempt <= cdnNeutralShortLimit; attempt++ {
		slot := r.finishTrialOutcome(k, id, "REMOTE_SMALL_EOF", true, now, 5568)
		if slot.SlotReleasedAt != now || slot.SlotReleaseReason != "REMOTE_SMALL_EOF" || slot.NeutralShortAttempt != uint32(attempt) || r.snapshot().Selection.ActiveTrial {
			t.Fatalf("slot release: %+v", slot)
		}
		v := r.cache[k]
		if int(v.NeutralShortStreak) != attempt || v.Qualified != id || v.Failures != 0 {
			t.Fatal("short poisoned strategy", v)
		}
		if _, ok := r.takeTrial(k, now, testSibling(false)); ok {
			t.Fatal("neutral retry skipped sibling")
		}
		_, ok := r.takeTrial(k, now, testSibling(true))
		if attempt < cdnNeutralShortLimit {
			if !ok {
				t.Fatal("next new flow waited cooldown", v)
			}
			if _, ok := r.takeTrial(k, now, testSibling(true)); ok {
				t.Fatal("max1 bypassed")
			}
		} else {
			if ok || v.TrialAfter.Before(now.Add(youtubeTrialCooldown)) || v.Reason != "CDN_TRIAL_ALL_SMALL_NO_DATA_LIMIT_COOLDOWN" {
				t.Fatal("unbounded neutral retries", v)
			}
		}
	}
	if r.selection.TrialFailures != 0 || r.selection.TrialSuccesses != 0 || r.selection.RemoteSmallEOFInconclusive != cdnNeutralShortLimit {
		t.Fatal(r.selection)
	}
	if _, ok := r.takeTrial(k, now.Add(youtubeTrialCooldown), testSibling(true)); !ok || r.cache[k].NeutralShortStreak != 0 {
		t.Fatal("cooldown never renews bounded budget")
	}
	m.trial = false // The direct-runtime test owns its mock exposure; no late finalization.
}

func TestCDNCallbackLateCloseCannotReleaseFastRetryOfSameSubgroup(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", RemoteFIN: 1}, io.EOF)
	m.failure("REMOTE_EOF_AFTER_REPLY")
	if _, ok := r.takeTrial(k, time.Now(), testSibling(true)); !ok {
		t.Fatal("next segment blocked")
	}
	m.Close()
	if !r.trialActive || r.trialKey != k || r.trialStrategy != id || r.selection.TrialInconclusive != 1 {
		t.Fatal("old Close released new same-group trial", r.snapshot())
	}
	if len(r.trials) != 1 || r.trials[0].SlotActive || r.trials[0].SlotReleasedAt.IsZero() || r.trials[0].SlotReleaseReason != "REMOTE_SMALL_EOF" {
		t.Fatal("lost per-trial release", r.trials)
	}
}

func TestCDNRealFailureAfterNeutralRetryKeepsCooldown(t *testing.T) {
	_, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	now := time.Now()
	r.finishTrialOutcome(k, id, "REMOTE_SMALL_EOF", true, now, 5568)
	r.takeTrial(k, now, testSibling(true))
	r.finishTrialOutcome(k, id, "FAILED", true, now, 5568)
	v := r.cache[k]
	if v.Qualified != "" || v.NeutralShortStreak != 0 || v.TrialAfter.Before(now.Add(youtubeTrialCooldown)) || r.selection.TrialFailures != 1 || r.selection.FailedAfterReply != 1 {
		t.Fatal(v, r.selection)
	}
	if _, ok := r.takeTrial(k, now, testSibling(true)); ok {
		t.Fatal("hard failure got fast retry")
	}
}
