package clientservice

import (
	"context"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestCDNColdBackgroundShortResponseRetainsGuardedTrial(t *testing.T) {
	server, roots := youtubeTLSHTTPFixture(t, "www.youtube.com", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "fixture: public page is not a media segment", http.StatusForbidden)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := browserproxy.ProbeOriginTransfer(ctx, "www.youtube.com", "/", roots, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if result.Status != http.StatusForbidden || result.TLSVersion == 0 || youtubeTransferOK(result) {
		t.Fatalf("fixture must verify TLS but fail public bulk criteria: %+v", result)
	}
	for _, hint := range []bool{false, true} {
		t.Run(map[bool]string{false: "visible-SNI", true: "DNS-hint"}[hint], func(t *testing.T) {
			c, cur, q, p := youtubeFixture(t)
			q.Host = "rr1---sn-cold.googlevideo.com"
			q.HintOnly = hint
			r := c.browser.youtube
			k := youtubeScope(cur, q)
			now := time.Now()
			learned, ok := r.takeRecheck(k, now)
			if !ok {
				t.Fatal("cold background check was not admitted")
			}
			id := r.nextCandidate(k, learned)
			public := q
			public.Host = "www.youtube.com"
			// Same callback order as youtubeBackgroundRecheck. Only committed
			// packet transformation is a seam; TLS/HTTP above use a real socket.
			c.recordLocalProbe(public, p, id, result, true)
			r.backgroundFailure(k, id, "BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM")
			r.endRecheck()
			if v := r.cache[k]; v.Qualified != id || v.Confirmed || v.Stage != "RELAY" {
				t.Fatalf("public failure discarded trial qualification or claimed LOCAL success: %+v", v)
			}
			if s := r.snapshot().Selection; s.BackgroundFailures != 1 || s.Trials != 0 || s.PeerProofs != 0 {
				t.Fatalf("public failure must remain visible without granting media success: %+v", s)
			}
			endpoint := cdnEndpoint{q.Host, p.Destination.String()}
			peer := testSibling(true)
			peer.MediaRequired = true
			peer.MediaBytes = cdnStrongBytes
			if _, _, ok := r.takeEndpointTrial(k, now, peer, endpoint); ok {
				t.Fatal("trial without >1MiB scoped RELAY traffic")
			}
			peer.MediaBytes++
			chosen, token, ok := r.takeEndpointTrial(k, now, peer, endpoint)
			if !ok || chosen != id {
				t.Fatal("next eligible new flow still cannot trial the committed strategy", chosen, r.cache[k])
			}
			if _, _, ok := r.takeEndpointTrial(k, now, peer, endpoint); ok {
				t.Fatal("more than one unproven trial")
			}
			meter := &youtubeMeter{r: r, key: k, stage: "LOCAL", strategy: id, trial: true, trialID: token, host: q.Host, destination: p.Destination.String(), rx: 17000}
			meter.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
			// A subsequent public check must not erase a real media failure,
			// its endpoint negative TTL, or its three-minute trial cooldown.
			r.backgroundFailure(k, id, "BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM")
			if _, _, ok := r.takeEndpointTrial(k, now.Add(time.Second), peer, endpoint); ok {
				t.Fatal("public result bypassed real-flow cooldown")
			}
			if _, _, ok := r.takeEndpointTrial(k, now.Add(youtubeTrialCooldown+time.Second), peer, endpoint); ok {
				t.Fatal("public result bypassed endpoint failure TTL")
			}
		})
	}
}

func TestCDNBackgroundFailureCannotBorrowOrReviveTransformProof(t *testing.T) {
	for _, cause := range []string{"uncommitted", "other-network", "other-profile", "other-hint-mode", "ordinary-host", "expired", "real-media-failure"} {
		t.Run(cause, func(t *testing.T) {
			c, cur, q, p := youtubeFixture(t)
			r := c.browser.youtube
			k := youtubeScope(cur, q)
			id := r.order[0]
			q.Host = "www.youtube.com"
			switch cause {
			case "other-network":
				p.Network = "other-network"
			case "other-profile":
				q.Owner.Profile = "other-profile"
			case "other-hint-mode":
				q.HintOnly = !q.HintOnly
			case "ordinary-host":
				q.Host = "vk.ru"
			}
			c.recordLocalProbe(q, p, id, browserproxy.ProbeResult{Failure: "NETWORK_TIMEOUT", Phase: "ORIGIN_TLS"}, cause != "uncommitted")
			if cause == "expired" {
				r.qualifications[youtubeQualification{k.Network, k.Profile, id, k.HintOnly}] = time.Now().Add(-time.Second)
			}
			if cause == "real-media-failure" {
				r.failed(k, "LOCAL", id, "MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED", time.Now())
			}
			r.backgroundFailure(k, id, "BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM")
			if got, ok := r.takeTrial(k, time.Now().Add(youtubeTrialCooldown), testSibling(true)); ok {
				t.Fatal("invalid/rejected proof admitted a media trial", got)
			}
			if stage, _ := r.choose(k, time.Now()); stage != "RELAY" {
				t.Fatal("invalid/rejected proof granted LOCAL", stage)
			}
		})
	}
}

func TestCDNBackgroundFailurePreservesLiveMediaConfirmation(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	r := c.browser.youtube
	k := youtubeScope(cur, q)
	confirmed, probing := r.order[1], r.order[0]
	now := time.Now()
	r.confirmed(k, "LOCAL", confirmed, now)
	until := r.cache[k].Until
	q.Host = "www.youtube.com"
	c.recordLocalProbe(q, p, probing, browserproxy.ProbeResult{Failure: "NETWORK_TIMEOUT"}, true)
	r.backgroundFailure(k, probing, "BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM")
	if stage, id := r.choose(k, now); stage != "LOCAL" || id != confirmed || !r.cache[k].Until.Equal(until) {
		t.Fatal("public failure replaced or extended the real media decision", r.cache[k])
	}
}

func TestCDNCanTrialWithCommittedTransformDespiteSilentPublicTLS(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	r := c.browser.youtube
	k := youtubeKey{Network: "fixture-net", Profile: "chrome", Domain: "googlevideo:sn-fixture", Port: 443}
	q := browserproxy.Request{Host: "www.youtube.com", Owner: browserproxy.Owner{Profile: k.Profile}}
	p := browserproxy.Plan{Network: k.Network}
	failed := browserproxy.ProbeResult{Failure: "NETWORK_TIMEOUT", Phase: "ORIGIN_TLS"}
	c.recordLocalProbe(q, p, "candidate", failed, false)
	if r.qualified(k, "candidate", time.Now()) {
		t.Fatal("no transform qualified")
	}
	q.Host = "vk.ru"
	c.recordLocalProbe(q, p, "candidate", failed, true)
	if r.qualified(k, "candidate", time.Now()) {
		t.Fatal("ordinary host qualified YouTube")
	}
	q.Host = "www.youtube.com"
	c.recordLocalProbe(q, p, "candidate", failed, true)
	if !r.qualified(k, "candidate", time.Now()) {
		t.Fatal("committed transform should permit guarded trial despite failed public prerequisite")
	}
	r.completeCDNQualification(k, "candidate", time.Now())
	if _, ok := r.takeTrial(k, time.Now(), testSibling(false)); ok {
		t.Fatal("trial without live relay sibling")
	}
	if _, ok := r.takeTrial(k, time.Now(), testSibling(true)); !ok {
		t.Fatal("qualified CDN trial stayed stuck")
	}
	r.finishTrial(k, "candidate", false, true, time.Now())
	if r.cache[k].Stage != "RELAY" || r.cache[k].Confirmed {
		t.Fatal("trial failure declared LOCAL")
	}
	other := k
	other.Network = "different"
	if r.qualified(other, "candidate", time.Now()) {
		t.Fatal("proof crossed network")
	}
	other = k
	other.Profile = "edge"
	if r.qualified(other, "candidate", time.Now()) {
		t.Fatal("proof crossed browser profile")
	}
	if r.qualified(k, "different-plan", time.Now()) {
		t.Fatal("proof crossed strategy")
	}
}

func TestCDNBackgroundSelectsExactSustainedPublicProofInsteadOfCatalogPrior(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Source = netip.MustParseAddrPort("192.0.2.2:51000")
	r := c.browser.youtube
	k := youtubeScope(cur, q)
	weak, strong := r.order[0], r.order[1]
	public := q
	public.Host = "www.youtube.com"
	p.Network = cur.network
	c.recordLocalProbe(public, p, weak, browserproxy.ProbeResult{Failure: "NETWORK_TIMEOUT"}, true)
	c.recordLocalProbe(public, p, strong, browserproxy.ProbeResult{Status: 200, TLSVersion: 0x304, BodyBytes: 131073}, true)
	r.completeCDNQualification(k, weak, time.Now())
	c.youtubeBackgroundRecheck(cur, q, p, k)
	id, ok := r.takeTrial(k, time.Now(), testSibling(true))
	if !ok || id != strong {
		t.Fatal("public proof was ignored", id, strong, r.cache[k])
	}
	r.finishTrial(k, id, false, false, time.Now())
}
