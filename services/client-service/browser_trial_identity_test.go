package clientservice

import (
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"io"
	"testing"
	"time"
)

func TestFailedCallbackEndsCDNTrialWithoutReadOrClose(t *testing.T) {
	m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	m.rx = 203
	m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	if r.snapshot().Selection.ActiveTrial || r.selection.TrialFailures != 1 {
		t.Fatalf("hard terminal callback still holds max1: %+v", r.selection)
	}
}

func TestCDNTrialNeedsBulkSameHostOrClusterWithoutRRClassifier(t *testing.T) {
	u := &browserRelayUsage{}
	now := time.Now()
	add := func(host string, n uint64) {
		id := u.beginVideo(videoPerformance{Profile: "chrome", Network: "net", Port: 443, Domain: host, Started: now})
		u.mu.Lock()
		u.videoIO(id, 1000, n, now)
		u.mu.Unlock()
	}
	add("r1.googlevideo.com", 10*cdnStrongBytes)
	if u.mediaTrialSibling("chrome", "net", "r2.googlevideo.com", now).MediaBytes != 0 {
		t.Fatal("unclassified is not a proven cluster")
	}
	host := "rr5---sn-media.googlevideo.com"
	add("rr6---sn-other.googlevideo.com", 10*cdnStrongBytes)
	add(host, 7000)
	peer := u.mediaTrialSibling("chrome", "net", host, now)
	if !peer.Eligible || !peer.MediaRequired || peer.MediaBytes != 0 {
		t.Fatal("unrelated bulk/control guessed segment", peer)
	}
	_, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	r.finishTrialOutcome(k, id, "INCONCLUSIVE", false, now.Add(-youtubeTrialCooldown), 0)
	endpoint := cdnEndpoint{host, "74.125.8.99:443"}
	if _, _, ok := r.takeEndpointTrial(k, now, peer, endpoint); ok || r.cache[k].TrialAdmission != "SCOPED_BULK_RELAY_NOT_OBSERVED" {
		t.Fatal(r.cache[k])
	}
	add(host, cdnStrongBytes+1) // rr5 itself can qualify; no rrN blacklist.
	peer = u.mediaTrialSibling("chrome", "net", host, now)
	if peer.MediaMatch != "EXACT_HOST" || peer.MediaBytes <= cdnStrongBytes {
		t.Fatal(peer)
	}
	if _, _, ok := r.takeEndpointTrial(k, now, peer, endpoint); !ok {
		t.Fatal("bulk host not admitted", r.cache[k])
	}
	if u.mediaTrialSibling("edge", "net", host, now).MediaBytes != 0 || u.mediaTrialSibling("chrome", "net", host, now.Add(cdnSiblingTTL+time.Millisecond)).MediaBytes != 0 {
		t.Fatal("bulk proof crossed scope/TTL")
	}
	clusterPeer := u.mediaTrialSibling("chrome", "net", "rr1---sn-media.googlevideo.com", now)
	if clusterPeer.MediaMatch != "SAME_SUBGROUP" {
		t.Fatal(clusterPeer)
	}
}

func TestCDNActiveIdentityDistinguishesFastRetryOfSameSubgroup(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{RemoteFIN: 1}, io.EOF)
	old := r.trialID
	m.trialID = old
	m.host = "rr4---sn-media.googlevideo.com"
	m.destination = "74.125.8.99:443"
	m.failure("REMOTE_EOF_AFTER_REPLY")
	if r.snapshot().Selection.ActiveTrial {
		t.Fatal("neutral still active")
	}
	peer := testSibling(true)
	peer.MediaRequired = true
	peer.MediaBytes = cdnStrongBytes + 1
	endpoint := cdnEndpoint{"rr5---sn-media.googlevideo.com", "74.125.8.100:443"}
	_, token, ok := r.takeEndpointTrial(k, time.Now(), peer, endpoint)
	if !ok || token == old {
		t.Fatal("retry identity not unique")
	}
	r.trialRecord = 2
	r.records[2] = youtubeRecord{cdnTrialSlot: cdnTrialSlot{TrialID: token}, ID: 2, Domain: endpoint.Host, Destination: endpoint.Address, Active: true, TrialResult: "PROBE_WAITING_DATA"}
	r.finishTrialOutcomeFor(old, k, id, "REMOTE_SMALL_EOF", true, time.Now(), 6735)
	m.Close()
	s := r.snapshot().Selection
	if !s.ActiveTrial || s.ActiveTrialID != token || s.ActiveRecordID != 2 || s.ActiveHost != endpoint.Host || s.ActiveDestination != endpoint.Address || s.ActiveRecordResult != "PROBE_WAITING_DATA" {
		t.Fatal("old terminal confused with new exposure", s)
	}
}

func TestCDNStallQuarantinesOnlyHostIPStrategy(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	e := cdnEndpoint{"rr5---sn-media.googlevideo.com", "74.125.8.99:443"}
	r.trialEndpoint = e
	m.trialID = r.trialID
	m.host = e.Host
	m.destination = e.Address
	m.rx = 203
	m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	v := r.cache[k]
	if r.trialActive || v.Qualified != id || v.Tried != 0 || r.selection.TrialFailures != 1 || r.selection.FailedAfterReply != 1 || v.TrialAfter.Before(time.Now().Add(2*time.Minute)) {
		t.Fatal("one endpoint poisoned subgroup", v, r.selection)
	}
	v.Stage = "LOCAL"
	v.Strategy = id
	v.Confirmed = true
	v.Until = time.Now().Add(youtubeLearnTTL)
	r.cache[k] = v
	if stage, _ := r.chooseEndpoint(k, e, time.Now()); stage != "RELAY" {
		t.Fatal("bad endpoint retried")
	}
	for _, other := range []cdnEndpoint{{e.Host, "74.125.8.100:443"}, {"rr6---sn-media.googlevideo.com", e.Address}} {
		if stage, _ := r.chooseEndpoint(k, other, time.Now()); stage != "LOCAL" {
			t.Fatal("healthy peer quarantined", other)
		}
	}
	if stage, _ := r.chooseEndpoint(k, e, time.Now().Add(youtubeLearnTTL+time.Second)); stage == "LOCAL" {
		t.Fatal("group TTL expired")
	}
	r.mu.Lock()
	bad := r.endpointBlockedLocked(k, id, e, time.Now().Add(youtubeLearnTTL+time.Second))
	r.mu.Unlock()
	if bad {
		t.Fatal("permanent endpoint pin")
	}
}

func TestCDNTrialUsesQualifiedAlternativeForBlockedEndpoint(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Now()
	endpoint := cdnEndpoint{"rr5---sn-media.googlevideo.com", "74.125.8.99:443"}
	other := cdnEndpoint{endpoint.Host, "74.125.8.100:443"}
	key := youtubeKey{"net", "chrome", youtubeSubgroup(endpoint.Host), 443, false}
	first, alternate := r.order[0], r.order[1]
	for _, strategy := range []string{first, alternate} {
		r.qualifications[youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}] = now.Add(youtubeLearnTTL)
	}
	r.completeCDNQualification(key, first, now)
	peer := testSibling(true)
	peer.MediaRequired = true
	peer.MediaBytes = cdnStrongBytes + 1

	chosen, token, ok := r.takeEndpointTrial(key, now, peer, endpoint)
	if !ok || chosen != first {
		t.Fatalf("initial trial = %q, admitted %v; want %q", chosen, ok, first)
	}
	failedAt := now.Add(time.Second)
	if !r.endpointFailed(key, first, endpoint, "ORIGIN_SILENT", failedAt) {
		t.Fatal("initial failure did not quarantine the endpoint and strategy")
	}
	r.finishTrialOutcomeFor(token, key, first, "FAILED", false, failedAt, 0)
	readyAt := failedAt.Add(youtubeTrialCooldown)
	if _, _, ok := r.takeEndpointTrial(key, readyAt.Add(-time.Millisecond), peer, endpoint); ok || r.cache[key].TrialAdmission != "SUBGROUP_COOLDOWN" {
		t.Fatal("alternate must wait for the subgroup cooldown", r.cache[key])
	}
	noBulk := peer
	noBulk.MediaBytes = cdnStrongBytes
	if _, _, ok := r.takeEndpointTrial(key, readyAt, noBulk, endpoint); ok || r.cache[key].TrialAdmission != "SCOPED_BULK_RELAY_NOT_OBSERVED" {
		t.Fatal("alternate must have scoped bulk relay evidence", r.cache[key])
	}

	chosen, alternateToken, ok := r.takeEndpointTrial(key, readyAt, peer, endpoint)
	if !ok || chosen != alternate || alternateToken == token {
		t.Fatalf("retry = %q, admitted %v, reason %s; want a new trial of %q", chosen, ok, r.cache[key].TrialAdmission, alternate)
	}
	if _, _, ok := r.takeEndpointTrial(key, readyAt, peer, other); ok || r.cache[key].TrialAdmission != "GLOBAL_TRIAL_ACTIVE" {
		t.Fatal("alternate must occupy the existing global slot", r.cache[key])
	}
	if !r.endpointFailed(key, alternate, endpoint, "ORIGIN_SILENT", readyAt) {
		t.Fatal("alternate failure did not quarantine its strategy")
	}
	r.finishTrialOutcomeFor(alternateToken, key, alternate, "FAILED", false, readyAt, 0)
	nextAt := readyAt.Add(youtubeTrialCooldown)
	for _, target := range []cdnEndpoint{endpoint, other} {
		if _, _, ok := r.takeEndpointTrial(key, nextAt.Add(-time.Millisecond), peer, target); ok || r.cache[key].TrialAdmission != "SUBGROUP_COOLDOWN" {
			t.Fatal("alternate failure must keep the cooldown for the whole subgroup", target, r.cache[key])
		}
	}
	if _, _, ok := r.takeEndpointTrial(key, nextAt, peer, endpoint); ok || r.cache[key].TrialAdmission != "ENDPOINT_STRATEGY_NEGATIVE_TTL" {
		t.Fatal("endpoint with no eligible strategy must stay on relay", r.cache[key])
	}
	if chosen, _, ok := r.takeEndpointTrial(key, nextAt, peer, other); !ok || chosen != first {
		t.Fatalf("other endpoint = %q, admitted %v; want %q", chosen, ok, first)
	}
}

func TestCDNAlternateTrialUsesOnlyItsOwnSuccessEvidence(t *testing.T) {
	for _, outcome := range []string{"closed-flows", "running"} {
		t.Run(outcome, func(t *testing.T) {
			r := newYoutubeRuntime()
			now := time.Now()
			endpoint := cdnEndpoint{"rr5---sn-media.googlevideo.com", "74.125.8.99:443"}
			key := youtubeKey{"net", "chrome", youtubeSubgroup(endpoint.Host), 443, false}
			first, alternate := r.order[0], r.order[1]
			for _, strategy := range []string{first, alternate} {
				r.qualifications[youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}] = now.Add(youtubeLearnTTL)
			}
			r.completeCDNQualification(key, first, now)
			v := r.cache[key]
			v.Streak = youtubeTrialSuccesses - 1
			v.VerifiedBytes = 128 * 1024
			r.cache[key] = v
			if !r.endpointFailed(key, first, endpoint, "ORIGIN_SILENT", now) {
				t.Fatal("initial failure did not quarantine the endpoint and strategy")
			}
			peer := testSibling(true)
			peer.MediaRequired = true
			peer.MediaBytes = cdnStrongBytes + 1
			chosen, token, ok := r.takeEndpointTrial(key, now, peer, endpoint)
			if !ok || chosen != alternate {
				t.Fatal("no alternate trial", chosen, r.cache[key])
			}
			if outcome == "running" {
				if !r.promoteRunningFor(token, key, alternate, cdnStrongBytes+1, now) {
					t.Fatal("valid sustained proof for the active alternate was ignored")
				}
				if v := r.cache[key]; !v.Confirmed || v.Stage != "LOCAL" || v.Strategy != alternate || v.Streak != 1 || r.trialActive {
					t.Fatal("running alternate inherited the preferred strategy's proof or kept the slot", v)
				}
			} else {
				const received = 96 * 1024
				for trial := 1; trial < youtubeTrialSuccesses; trial++ {
					r.finishTrialOutcomeFor(token, key, alternate, "SUCCESS", true, now, received)
					if v := r.cache[key]; v.Confirmed || v.Qualified != first || v.Streak != youtubeTrialSuccesses-1 || v.VerifiedBytes != 128*1024 {
						t.Fatal("unconfirmed alternate changed the preferred strategy's proof", v)
					}
					now = now.Add(youtubeTrialCooldown)
					chosen, token, ok = r.takeEndpointTrial(key, now, peer, endpoint)
					if !ok || chosen != alternate {
						t.Fatal("qualified alternate was lost before confirmation", chosen, r.cache[key])
					}
				}
				r.finishTrialOutcomeFor(token, key, alternate, "SUCCESS", true, now, received)
				if v := r.cache[key]; !v.Confirmed || v.Stage != "LOCAL" || v.Strategy != alternate || v.Streak != youtubeTrialSuccesses || v.VerifiedBytes != received || r.trialActive {
					t.Fatal("three successes of the alternate did not confirm its own LOCAL route", v)
				}
			}
			deadline := r.cache[key].Until
			now = now.Add(time.Second)
			r.completeCDNQualification(key, first, now)
			if stage, id := r.chooseEndpoint(key, endpoint, now); stage != "LOCAL" || id != alternate || !r.cache[key].Until.Equal(deadline) {
				t.Fatal("background proof replaced or renewed a live alternate", stage, id, r.cache[key])
			}
		})
	}
}

func TestCDNTrialKeepsQualifiedAlternativeAfterLocalConfirmation(t *testing.T) {
	now := time.Now()
	endpoint := cdnEndpoint{"rr5---sn-media.googlevideo.com", "74.125.8.99:443"}
	key := youtubeKey{"net", "chrome", youtubeSubgroup(endpoint.Host), 443, false}
	peer := testSibling(true)
	peer.MediaRequired = true
	peer.MediaBytes = cdnStrongBytes + 1
	for _, tc := range []struct {
		name       string
		proofTTL   time.Duration
		tried      uint64
		wantReason string
	}{
		{"live proof", youtubeLearnTTL, 0, "ADMITTED"},
		{"expired proof", 2 * time.Second, 0, "STRATEGY_PROOF_EXPIRED"},
		{"sweep already excluded the alternate", youtubeLearnTTL, 1 << 1, "ENDPOINT_STRATEGY_NEGATIVE_TTL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newYoutubeRuntime()
			first, alternate := r.order[0], r.order[1]
			for _, strategy := range []string{first, alternate} {
				r.qualifications[youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}] = now.Add(tc.proofTTL)
			}
			r.completeCDNQualification(key, first, now)
			v := r.cache[key]
			v.Tried = tc.tried
			r.cache[key] = v
			r.confirmed(key, "LOCAL", first, now.Add(time.Second))
			failedAt := now.Add(3 * time.Second)
			if !r.endpointFailed(key, first, endpoint, "ORIGIN_SILENT", failedAt) {
				t.Fatal("LOCAL failure did not block the old strategy for the endpoint")
			}
			chosen, token, reason, _ := r.decideEndpointTrial(key, failedAt, peer, endpoint)
			if reason != tc.wantReason {
				t.Fatalf("admission = %s; want %s", reason, tc.wantReason)
			}
			if tc.wantReason == "ADMITTED" && (chosen != alternate || token == 0) {
				t.Fatalf("strategy = %q, trial = %d; want alternate %q and an active trial", chosen, token, alternate)
			}
			if tc.wantReason != "ADMITTED" && (chosen != "" || token != 0) {
				t.Fatalf("rejected strategy admitted a trial: strategy = %q, trial = %d", chosen, token)
			}
		})
	}
}

func TestCDNLocalConfirmationKeepsAnIndependentTrialCooldown(t *testing.T) {
	now := time.Now()
	r := newYoutubeRuntime()
	endpoint := cdnEndpoint{"rr5---sn-media.googlevideo.com", "74.125.8.99:443"}
	key := youtubeKey{"net", "chrome", youtubeSubgroup(endpoint.Host), 443, false}
	first, alternate := r.order[0], r.order[1]
	for _, strategy := range []string{first, alternate} {
		r.qualifications[youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}] = now.Add(youtubeLearnTTL)
	}
	r.completeCDNQualification(key, first, now)
	peer := testSibling(true)
	peer.MediaRequired = true
	peer.MediaBytes = cdnStrongBytes + 1
	strategy, token, reason, _ := r.decideEndpointTrial(key, now, peer, endpoint)
	if strategy != first || token == 0 || reason != "ADMITTED" {
		t.Fatalf("first trial = %q, %d, %s", strategy, token, reason)
	}
	failedAt := now.Add(time.Second)
	if !r.endpointFailed(key, first, endpoint, "ORIGIN_SILENT", failedAt) {
		t.Fatal("failed trial did not block its endpoint and strategy")
	}
	slot := r.finishTrialOutcomeFor(token, key, first, "FAILED", false, failedAt, 0)
	// A separate normal LOCAL connection succeeds on a different endpoint.
	r.confirmed(key, "LOCAL", first, failedAt.Add(time.Second))
	if _, token, reason, _ := r.decideEndpointTrial(key, slot.CooldownUntil.Add(-time.Millisecond), peer, endpoint); token != 0 || reason != "SUBGROUP_COOLDOWN" {
		t.Fatalf("before cooldown: trial = %d, reason = %s", token, reason)
	}
	if strategy, token, reason, _ := r.decideEndpointTrial(key, slot.CooldownUntil, peer, endpoint); strategy != alternate || token == 0 || reason != "ADMITTED" {
		t.Fatalf("after cooldown: strategy = %q, trial = %d, reason = %s", strategy, token, reason)
	}
}
