package clientservice

import (
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net/netip"
	"testing"
	"time"
)

func TestSelectionSubgroupsAndCatalogPlansAreIsolated(t *testing.T) {
	for _, host := range []string{"accounts.youtube.com", "www.youtube.com", "i.ytimg.com", "rr1---sn-abc.googlevideo.com", "rr2---sn-def.googlevideo.com"} {
		for _, other := range []string{"accounts.youtube.com", "www.youtube.com", "i.ytimg.com", "rr1---sn-abc.googlevideo.com", "rr2---sn-def.googlevideo.com"} {
			if host != other && youtubeSubgroup(host) == youtubeSubgroup(other) {
				t.Fatal("poisoned subgroup", host, other)
			}
		}
	}
	if youtubeSubgroup("rr1---sn-abc.googlevideo.com") != youtubeSubgroup("rr4---sn-abc.googlevideo.com") {
		t.Fatal("same CDN pool split")
	}
	e := browserDomainEvidence{YoutubeOnly: true, Ambiguous: true, Candidates: []string{"accounts.youtube.com", "rr1---sn-abc.googlevideo.com"}}
	if youtubeSameHintSubgroup(e) {
		t.Fatal("alphabetical shared IP hint authorized LOCAL")
	}
	e.Candidates = []string{"rr1---sn-abc.googlevideo.com", "rr2---sn-abc.googlevideo.com"}
	e.YoutubeSubgroup = "googlevideo:sn-abc"
	if !youtubeSameHintSubgroup(e) {
		t.Fatal("same CDN rejected")
	}
	c, cur, q, p := youtubeFixture(t)
	plans, _ := localstrategy.BundledCatalog().Compile()
	for _, plan := range plans {
		for _, hint := range []bool{false, true} {
			q.HintOnly = hint
			if id, engine := c.youtubeEngine(cur, q, p, plan.ID); id == "" || engine == nil {
				t.Fatal("catalog not usable", plan.ID, hint)
			}
		}
	}
}
func TestCDNTrialRequiresPrequalificationLivePeerCooldownAndThreeFlows(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Now()
	k := youtubeKey{"net", "chrome", "googlevideo:sn-a", 443, false}
	id := r.order[0]
	if _, ok := r.takeTrial(k, now, testSibling(true)); ok {
		t.Fatal("unqualified")
	}
	r.cache[k] = youtubeLearn{Stage: "RELAY", Qualified: id, Until: now.Add(youtubeLearnTTL)}
	if _, ok := r.takeTrial(k, now, testSibling(true)); ok {
		t.Fatal("no two-origin proof")
	}
	r.qualifications[youtubeQualification{k.Network, k.Profile, id, k.HintOnly}] = now.Add(youtubeLearnTTL)
	if _, ok := r.takeTrial(k, now, testSibling(false)); ok {
		t.Fatal("no active relay sibling")
	}
	for trial := 0; trial < 3; trial++ {
		if _, ok := r.takeTrial(k, now, testSibling(true)); !ok {
			t.Fatal("trial not admitted", trial, r.cache[k])
		}
		if _, ok := r.takeTrial(k, now, testSibling(true)); ok {
			t.Fatal("concurrent trial")
		}
		r.finishTrial(k, id, true, true, now)
		if stage, _ := r.choose(k, now); (stage == "LOCAL") != (trial == 2) {
			t.Fatal("premature/missing promotion", trial, stage)
		}
		if trial < 2 {
			if _, ok := r.takeTrial(k, now.Add(time.Minute), testSibling(true)); ok {
				t.Fatal("cooldown ignored")
			}
		}
		now = now.Add(youtubeTrialCooldown)
	}
	r.failed(k, "LOCAL", id, "MIDSTREAM_STALL", now)
	if stage, _ := r.choose(k, now); stage != "RELAY" {
		t.Fatal("degraded LOCAL still selected")
	}
	if r.cache[k].Streak != 0 {
		t.Fatal("broken consecutive success")
	}
}
func TestCDNTrialFailureAfterReplyIsVisibleAndNextCandidateEventuallyRetried(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Now()
	k := youtubeKey{"net", "chrome", "googlevideo:sn-a", 443, false}
	id := r.order[0]
	r.cache[k] = youtubeLearn{Stage: "RELAY", Qualified: id, Until: now.Add(youtubeLearnTTL)}
	r.qualifications[youtubeQualification{k.Network, k.Profile, id, false}] = now.Add(youtubeLearnTTL)
	if _, ok := r.takeTrial(k, now, testSibling(true)); !ok {
		t.Fatal("setup")
	}
	r.finishTrial(k, id, false, true, now)
	s := r.snapshot().Selection
	if s.Trials != 1 || s.TrialFailures != 1 || s.FailedAfterReply != 1 || s.ActiveTrial {
		t.Fatal(s)
	}
	// The cooldown is bounded even after every catalog plan has failed. No reset
	// to the first strategy simply because the positive route TTL elapsed.
	for i := 0; i < len(r.order)*2; i++ {
		v, ok := r.takeRecheck(k, now.Add(time.Hour))
		if !ok {
			t.Fatal("permanent RELAY", i, r.cache[k])
		}
		next := r.nextCandidate(k, v)
		if next == "" {
			t.Fatal("empty sweep")
		}
		r.endRecheck()
		r.failed(k, "LOCAL", next, "probe failed", now)
		now = now.Add(time.Hour)
	}
}
func TestRankingIsBoundedAndDoesNotBorrowNetworkOrHintOutcome(t *testing.T) {
	r := newYoutubeRuntime()
	k := youtubeKey{"net", "chrome", "www.youtube.com", 443, false}
	other := k
	other.Network = "other"
	preferred := r.order[2]
	r.score(k, preferred, true, time.Now())
	if r.nextCandidate(k, youtubeLearn{}) != preferred || r.nextCandidate(other, youtubeLearn{}) == preferred {
		t.Fatal("score selection/isolation")
	}
	other = k
	other.HintOnly = true
	if r.nextCandidate(other, youtubeLearn{}) == preferred {
		t.Fatal("borrowed SNI result for ECH")
	}
	p := browserproxy.ProbeResult{Status: 200, TLSVersion: 0x0304, BodyBytes: 100000, Failure: "NETWORK_TIMEOUT"}
	if youtubeTransferOK(p) {
		t.Fatal("partial failed response accepted")
	}
}

func TestBothPublicOriginsRequiredBeforeCDNTrial(t *testing.T) {
	k := youtubeKey{Domain: "googlevideo:sn-abc"}
	for _, failed := range []string{"www.youtube.com", "i.ytimg.com", ""} {
		visited := []string{}
		passed := youtubePrerequisites(k, "r1.googlevideo.com", func(origin [2]string) bool { visited = append(visited, origin[0]); return origin[0] != failed })
		if passed != (failed == "") {
			t.Fatal("single public response enough", failed, visited)
		}
		if failed != "www.youtube.com" && (len(visited) != 2 || visited[0] != "www.youtube.com" || visited[1] != "i.ytimg.com") {
			t.Fatal("prerequisites not checked", visited)
		}
	}
}
func TestSelectionStopRejectsNewBackgroundWorker(t *testing.T) {
	r := newYoutubeRuntime()
	k := youtubeKey{Network: "net"}
	if _, ok := r.takeRecheck(k, time.Now()); !ok {
		t.Fatal("worker not admitted")
	}
	done := make(chan struct{})
	go func() { r.stop(); close(done) }()
	select {
	case <-done:
		t.Fatal("stop did not wait for active probe")
	case <-time.After(10 * time.Millisecond):
	}
	r.endRecheck()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker leaked")
	}
	if _, ok := r.takeRecheck(k, time.Now().Add(time.Hour)); ok {
		t.Fatal("probe after shutdown")
	}
}

func TestSharedIPSubgroupCheckPrecedesDiagnosticTruncation(t *testing.T) {
	var x browserDomainIndex
	now := time.Now()
	ip := netip.MustParseAddr("74.125.111.131")
	rows := []wp.DNSCacheEntry{}
	for _, h := range []string{"a---sn-abc.googlevideo.com", "b---sn-abc.googlevideo.com", "c---sn-abc.googlevideo.com", "d---sn-abc.googlevideo.com", "e---sn-abc.googlevideo.com", "f---sn-abc.googlevideo.com", "g---sn-abc.googlevideo.com", "h---sn-abc.googlevideo.com", "z.youtube.com"} {
		rows = append(rows, wp.DNSCacheEntry{Name: h, Address: ip.String(), TTL: 60})
	}
	x.replace("net", rows, nil, now)
	e := x.profileEvidence("net", "chrome", ip, "", now)
	if !e.YoutubeOnly || len(e.Candidates) != 8 || youtubeSameHintSubgroup(e) {
		t.Fatal("9th mixed subgroup truncated into LOCAL authorization", e)
	}
}

func TestCDNPrefersSustainedScopedProofAndCannotResetTrialCooldown(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Now()
	k := youtubeKey{"net", "chrome", "googlevideo:sn-a", 443, false}
	weak, strong := r.order[0], r.order[1]
	for _, id := range []string{weak, strong} {
		r.qualifications[youtubeQualification{k.Network, k.Profile, id, k.HintOnly}] = now.Add(youtubeLearnTTL)
	}
	r.sustained[youtubeQualification{k.Network, k.Profile, strong, k.HintOnly}] = now.Add(youtubeLearnTTL)
	if got := r.cdnCandidate(k, youtubeLearn{}, cdnEndpoint{}, now); got != strong {
		t.Fatal("picked unproven catalog prior", got, strong)
	}
	other := k
	other.Network = "other"
	if r.cdnCandidate(other, youtubeLearn{}, cdnEndpoint{}, now) != "" {
		t.Fatal("cross-network proof")
	}
	r.completeCDNQualification(k, strong, now)
	if got, ok := r.takeTrial(k, now, testSibling(true)); !ok || got != strong {
		t.Fatal("wrong admitted strategy", got, ok)
	}
	r.finishTrial(k, strong, true, true, now, 70000)
	r.completeCDNQualification(k, strong, now.Add(time.Minute))
	if _, ok := r.takeTrial(k, now.Add(time.Minute), testSibling(true)); ok {
		t.Fatal("requalification bypassed 3min cooldown")
	}
	if got, ok := r.takeTrial(k, now.Add(youtubeTrialCooldown), testSibling(true)); !ok || got != strong {
		t.Fatal("cooldown did not expire", got, ok)
	}
	r.finishTrial(k, strong, false, true, now.Add(youtubeTrialCooldown))
	v := r.cache[k]
	if v.Streak != 0 || v.Stage != "RELAY" || r.cdnCandidate(k, v, cdnEndpoint{}, now.Add(youtubeTrialCooldown)) == strong {
		t.Fatal("failed strategy immediately retried", v)
	}
}

func TestBackgroundCompletionCannotRebindOrPoisonAnActiveCDNTrial(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Now()
	k := youtubeKey{"net", "chrome", "googlevideo:sn-race", 443, false}
	first, second := r.order[0], r.order[1]
	r.qualifications[youtubeQualification{k.Network, k.Profile, first, k.HintOnly}] = now.Add(youtubeLearnTTL)
	r.completeCDNQualification(k, first, now)
	if _, ok := r.takeTrial(k, now, testSibling(true)); !ok {
		t.Fatal("no trial")
	}
	r.sustained[youtubeQualification{k.Network, k.Profile, second, k.HintOnly}] = now.Add(youtubeLearnTTL)
	r.completeCDNQualification(k, second, now)
	r.backgroundFailure(k, second, "BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM")
	if r.cache[k].Qualified != first {
		t.Fatal("background altered established trial binding", r.cache[k])
	}
	r.finishTrial(k, first, true, true, now, 70000)
	if r.selection.TrialSuccesses != 1 || r.cache[k].Streak != 1 {
		t.Fatal("successful trial was lost", r.cache[k])
	}
}
