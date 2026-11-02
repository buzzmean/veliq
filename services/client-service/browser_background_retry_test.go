package clientservice

import (
	"testing"
	"time"
)

func TestBackgroundCancellationKeepsSameTickMediaFailure(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	key := youtubeKey{"network", "chrome", "googlevideo:sn-tick", 443, false}
	lease, ok := r.takeRecheck(key, now)
	if !ok {
		t.Fatal("background admission missing")
	}
	defer r.endRecheck()
	strategy := r.order[0]
	r.completeCDNQualification(key, strategy, now)
	endpoint := cdnEndpoint{"rr1---sn-tick.googlevideo.com", "8.8.8.8:443"}
	sibling := testSibling(true)
	sibling.MediaRequired, sibling.MediaBytes = true, cdnStrongBytes+1
	chosen, token, ok := r.takeEndpointTrial(key, now, sibling, endpoint)
	if !ok || chosen != strategy {
		t.Fatal("foreground trial not admitted")
	}
	if !r.endpointFailed(key, strategy, endpoint, "MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED", now) {
		t.Fatal("endpoint failure not recorded")
	}
	r.finishTrialOutcomeFor(token, key, strategy, "FAILED", true, now, 64*1024)
	before := r.cache[key]
	if !before.Retry.Equal(lease.Retry) || before.TrialID == 0 || before.TrialAfter.IsZero() {
		t.Fatal("same-clock-tick collision not exercised")
	}
	negative := r.endpointNegative[cdnEndpointKey{key, endpoint, strategy}]
	r.cancelBackgroundRecheck(key, lease)
	if r.cache[key] != before || r.endpointNegative[cdnEndpointKey{key, endpoint, strategy}] != negative {
		t.Fatal("cancelled background task overwrote a real media failure with the same Retry timestamp")
	}
	if _, _, ok := r.takeEndpointTrial(key, now.Add(time.Second), sibling, endpoint); ok {
		t.Fatal("cancelled background probe bypassed media cooldown")
	}
}

func TestBackgroundCancellationReleasesUnchangedAndObservedReservations(t *testing.T) {
	for _, observe := range []bool{false, true} {
		r := newYoutubeRuntime()
		now := time.Now()
		key := youtubeKey{"network", "chrome", "googlevideo:sn-own", 443, false}
		lease, ok := r.takeRecheck(key, now)
		if !ok {
			t.Fatal("background admission missing")
		}
		if observe {
			if _, _, ok := r.takeEndpointTrial(key, now, testSibling(false), cdnEndpoint{}); ok {
				t.Fatal("unqualified observation became a trial")
			}
		}
		checks := r.cache[key].TrialChecks
		r.cancelBackgroundRecheck(key, lease)
		after := r.cache[key]
		r.endRecheck()
		if !after.Retry.IsZero() || after.Reason != "BACKGROUND_POLICY_CHANGED" || after.TrialChecks != checks {
			t.Fatal("unchanged/observed cancelled reservation retained delay or lost diagnostics", observe)
		}
	}
}
