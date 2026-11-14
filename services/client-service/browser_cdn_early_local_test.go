package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

func TestCDNEarlyLocalTrialAdmission(t *testing.T) {
	now := time.Now()
	key := youtubeKey{Network: "net", Profile: "chrome", Domain: "googlevideo:sn-lab", Port: 443}
	endpoint := cdnEndpoint{Host: "rr1---sn-lab.googlevideo.com", Address: "74.125.111.131:443"}
	for _, tc := range []struct {
		name         string
		configure    func(*youtubeRuntime)
		networkReady bool
		peer         relaySiblingEvidence
		want         string
	}{
		{"no arm", func(r *youtubeRuntime) { r.earlyTrialScope = nil }, true, relaySiblingEvidence{MediaRequired: true}, "SCOPED_BULK_RELAY_NOT_OBSERVED"},
		{"network guard", func(*youtubeRuntime) {}, false, relaySiblingEvidence{MediaRequired: true}, "SCOPED_BULK_RELAY_NOT_OBSERVED"},
		{"different scope", func(r *youtubeRuntime) {
			other := key
			other.Profile = "edge"
			r.earlyTrialScope = &other
		}, true, relaySiblingEvidence{MediaRequired: true}, "SCOPED_BULK_RELAY_NOT_OBSERVED"},
		{"expired proof", func(r *youtubeRuntime) {
			r.qualifications[youtubeQualification{key.Network, key.Profile, r.order[0], key.HintOnly}] = now
		}, true, relaySiblingEvidence{MediaRequired: true}, "STRATEGY_PROOF_EXPIRED"},
		{"cooldown", func(r *youtubeRuntime) {
			v := r.cache[key]
			v.TrialAfter = now.Add(time.Minute)
			r.cache[key] = v
		}, true, relaySiblingEvidence{MediaRequired: true}, "SUBGROUP_COOLDOWN"},
		{"global slot", func(r *youtubeRuntime) { r.trialActive = true }, true, relaySiblingEvidence{MediaRequired: true}, "GLOBAL_TRIAL_ACTIVE"},
		{"negative endpoint", func(r *youtubeRuntime) {
			r.endpointFailed(key, r.order[0], endpoint, "ORIGIN_SILENT", now)
		}, true, relaySiblingEvidence{MediaRequired: true}, "ENDPOINT_STRATEGY_NEGATIVE_TTL"},
		{"normal admission", func(*youtubeRuntime) {}, true, relaySiblingEvidence{Eligible: true, MediaRequired: true, MediaBytes: cdnStrongBytes + 1}, "ADMITTED"},
		{"no relay", func(*youtubeRuntime) {}, true, relaySiblingEvidence{MediaRequired: true}, cdnEarlyTrialAdmitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newYoutubeRuntime()
			r.earlyTrialScope = &key
			strategy := r.order[0]
			r.cache[key] = youtubeLearn{Stage: "RELAY", Qualified: strategy, Until: now.Add(youtubeLearnTTL)}
			r.qualifications[youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}] = now.Add(youtubeLearnTTL)
			tc.configure(r)
			armed := r.earlyTrialScope != nil
			_, token, reason := r.decideEndpointTrial(key, now, tc.peer, endpoint, tc.networkReady)
			if reason != tc.want {
				t.Fatalf("reason %q, want %q", reason, tc.want)
			}
			admitted := reason == "ADMITTED" || reason == cdnEarlyTrialAdmitted
			if (token != 0) != admitted || (r.earlyTrialScope != nil) != (armed && reason != cdnEarlyTrialAdmitted) {
				t.Fatal("incorrect trial identity or arm state", token, r.earlyTrialScope)
			}
			if reason == cdnEarlyTrialAdmitted {
				r.finishTrialOutcomeFor(token, key, strategy, "FAILED", false, now, 0)
				_, token, reason = r.decideEndpointTrial(key, now.Add(youtubeTrialCooldown+time.Second), tc.peer, endpoint, true)
				if token != 0 || reason != "SCOPED_BULK_RELAY_NOT_OBSERVED" {
					t.Fatal("early trial repeated", token, reason)
				}
			}
		})
	}
}

func TestCDNEarlyLocalTrialOneConcurrentAdmission(t *testing.T) {
	r := newYoutubeRuntime()
	now := time.Now()
	key := youtubeKey{Network: "net", Profile: "chrome", Domain: "googlevideo:sn-lab", Port: 443}
	endpoint := cdnEndpoint{Host: "rr1---sn-lab.googlevideo.com", Address: "74.125.111.131:443"}
	strategy := r.order[0]
	r.earlyTrialScope = &key
	r.cache[key] = youtubeLearn{Stage: "RELAY", Qualified: strategy, Until: now.Add(youtubeLearnTTL)}
	r.qualifications[youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}] = now.Add(youtubeLearnTTL)
	var wg sync.WaitGroup
	results := make(chan string, 12)
	for range cap(results) {
		wg.Go(func() {
			_, _, reason := r.decideEndpointTrial(key, now, relaySiblingEvidence{MediaRequired: true}, endpoint, true)
			results <- reason
		})
	}
	wg.Wait()
	close(results)
	admitted := 0
	for reason := range results {
		switch reason {
		case cdnEarlyTrialAdmitted:
			admitted++
		case "GLOBAL_TRIAL_ACTIVE":
		default:
			t.Fatal(reason)
		}
	}
	if admitted != 1 || r.selection.Trials != 1 {
		t.Fatal("expected one early trial", admitted, r.selection.Trials)
	}
}

func TestCDNEarlyLocalTrialComparedWithDefault(t *testing.T) {
	const payloadSize = 2 * 1024 * 1024
	for _, tc := range []struct {
		name       string
		early      bool
		localReady bool
	}{
		{"default", false, true},
		{"early-local-responds", true, true},
		{"early-local-silent", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cur, q, p := youtubeFixture(t)
			c.Backend = &youtubeTransformFixture{}
			q.Host = "rr1---sn-lab.googlevideo.com"
			r := c.browser.youtube
			key := youtubeScope(cur, q)
			strategy := r.order[0]
			now := time.Now()
			r.cache[key] = youtubeLearn{Stage: "RELAY", Qualified: strategy, Until: now.Add(youtubeLearnTTL)}
			r.qualifications[youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}] = now.Add(youtubeLearnTTL)
			if tc.early {
				r.earlyTrialScope = &key
			}
			server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte("v"), payloadSize))
			}))
			var relayOpens int
			open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
				switch plan.Policy.Action {
				case flowpolicy.DirectPlus:
					if !tc.localReady {
						a, b := net.Pipe()
						go func() {
							defer b.Close()
							_, _ = io.Copy(io.Discard, b)
						}()
						return a, nil
					}
				case flowpolicy.RelayRequired:
					relayOpens++
				default:
					return nil, errors.New("unexpected route for test connection")
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			raw, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			secure := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: q.Host, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
			if err := secure.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := secure.Handshake(); err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest("GET", "https://"+q.Host+"/video-fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Close = true
			if err := req.Write(secure); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(secure), req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			n, err := io.Copy(io.Discard, resp.Body)
			if err != nil || n != payloadSize || resp.StatusCode != http.StatusOK {
				t.Fatal(n, resp.StatusCode, err)
			}
			events := r.cdnDecisionSnapshot().Events
			if len(events) < 2 {
				t.Fatal(events)
			}
			switch {
			case !tc.early:
				if len(events) != 2 || events[0].Stage != "RELAY" || events[0].Admission != "SCOPED_BULK_RELAY_NOT_OBSERVED" || relayOpens != 1 {
					t.Fatal(events, relayOpens)
				}
			case tc.localReady:
				if len(events) != 2 || events[0].Stage != "LOCAL" || events[0].Admission != cdnEarlyTrialAdmitted || relayOpens != 0 {
					t.Fatal(events, relayOpens)
				}
			default:
				if len(events) != 3 || events[0].Stage != "LOCAL" || events[0].Admission != cdnEarlyTrialAdmitted || relayOpens != 1 ||
					events[2].Stage != "RELAY" || events[2].Reason != "ORIGIN_SILENT" || events[2].ConnectionID != events[0].ConnectionID {
					t.Fatal(events, relayOpens)
				}
				wait := events[2].At.Sub(events[1].At)
				if wait < 895*time.Millisecond || wait >= 4*time.Second {
					t.Fatal("unexpected local-to-relay delay", wait)
				}
				t.Logf("local open to relay open: %s", wait)
			}
			t.Logf("first route=%s relay opens=%d body bytes=%d", events[0].Stage, relayOpens, n)
		})
	}
}
