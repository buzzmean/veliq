//go:build windows

package clientservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

func browserAutoLocalFixture(t *testing.T) (*Controller, profilesResult, browserproxy.Request, browserproxy.Plan) {
	t.Helper()
	c, cur, q, p := newYouTubeLocalBetaRouteFixture(t)
	// Exercise the fallback ladder used by other browser origins in isolation.
	c.youtubeLocalBeta.setGeneration(false)
	c.mu.Lock()
	c.enabled, c.settings.Automatic = true, true
	c.mu.Unlock()
	p.YouTubeLocalGeneration = 0
	p.FirstFlightManaged = false
	p.Policy.Source = youtubeLadderSource
	q.Host = "rr4---sn-oj5hn5-55.googlevideo.com"
	p.Destination = netip.MustParseAddrPort("74.125.8.4:443")
	if c.youtubeLocalBetaStatus().Enabled || c.youtubeLocalBetaOriginScope(q) != 0 {
		t.Fatal("test fixture unexpectedly selected YouTube-specific policy")
	}
	if got, err := c.browserProfile(q.Owner); err != nil || !got.enabled {
		t.Fatal("real Windows Chrome owner did not enter AUTO", err)
	}
	return c, cur, q, p
}

func TestBrowserAutoLocalBeforeRelay(t *testing.T) {
	for _, tc := range []struct {
		name string
		okAt int
		want []flowpolicy.Action
	}{
		{"healthy DIRECT", 1, []flowpolicy.Action{flowpolicy.Direct}},
		{"cold alternate LOCAL", 3, []flowpolicy.Action{flowpolicy.Direct, flowpolicy.DirectPlus, flowpolicy.DirectPlus}},
		{"VPS after exhaustion", 5, []flowpolicy.Action{flowpolicy.Direct, flowpolicy.DirectPlus, flowpolicy.DirectPlus, flowpolicy.DirectPlus, flowpolicy.RelayRequired}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cur, q, p := browserAutoLocalFixture(t)
			server, roots := youtubeTLSHTTPFixture(t, q.Host)
			var actions []flowpolicy.Action
			var strategies []string
			var sourceBytes uint64
			open := func(ctx context.Context, request browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
				if request.Host != q.Host || actual.Destination != p.Destination || !actual.FirstFlightManaged {
					t.Errorf("unexpected opener scope: %s %+v", request.Host, actual)
				}
				actions = append(actions, actual.Policy.Action)
				strategies = append(strategies, actual.Policy.Strategy)
				if len(actions) != tc.okAt && len(actions) <= len(tc.want) {
					client, origin := net.Pipe()
					go func() {
						defer origin.Close()
						_, _ = io.Copy(io.Discard, origin)
					}()
					return client, nil
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			exchange := func(want flowpolicy.Action) {
				t.Helper()
				raw, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				conn := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: q.Host, MinVersion: tls.VersionTLS12})
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				req, _ := http.NewRequest("GET", "https://"+q.Host+"/video-fixture", nil)
				req.Close = true
				if err := req.Write(conn); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), req)
				if err != nil {
					t.Fatal(err)
				}
				n, err := io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 || n != 131072 {
					t.Fatalf("TLS/HTTP status=%d bytes=%d err=%v", response.StatusCode, n, err)
				}
				sourceBytes += uint64(n)
				if policy, _ := raw.(interface {
					CurrentTCPPolicy() (flowpolicy.Result, bool)
				}).CurrentTCPPolicy(); policy.Action != want {
					t.Fatalf("final route %s, want %s", policy.Action, want)
				}
			}
			exchange(tc.want[len(tc.want)-1])
			if !reflect.DeepEqual(actions, tc.want) {
				t.Fatalf("route order = %v, want %v", actions, tc.want)
			}
			events := c.browser.youtube.cdnDecisionSnapshot().Events
			if len(events) == 0 {
				t.Fatal("missing decision trace")
			}
			var local, vps, silent int
			for _, event := range events {
				if event.ConnectionID != events[0].ConnectionID {
					t.Fatalf("first-flight retry lost connection ID: %+v", events)
				}
				if event.Admission == "SCOPED_BULK_RELAY_NOT_OBSERVED" {
					t.Fatalf("old relay gate still used: %+v", events)
				}
				if event.Phase == "OPENED" && event.Stage == "RELAY" {
					vps++
				}
				if event.Phase == "OPENED" && event.Stage == "LOCAL" {
					local++
				}
				if event.Phase == "FAILED" && event.Reason == "ORIGIN_SILENT" {
					silent++
				}
			}
			var localRX uint64
			for _, stat := range c.browser.youtube.snapshot().Stages {
				if stat.Stage == "LOCAL" {
					localRX += stat.RX
				}
			}
			switch tc.okAt {
			case 1:
				if local != 0 || vps != 0 || silent != 0 {
					t.Fatal(local, vps, silent)
				}
			case 3:
				if local != 2 || vps != 0 || silent != 2 || localRX < sourceBytes || strategies[1] == strategies[2] {
					t.Fatal(local, vps, silent, localRX, strategies)
				}
				exchange(flowpolicy.DirectPlus)
				if len(actions) != 4 || strategies[3] != strategies[2] {
					t.Fatalf("confirmed alternate LOCAL was not applied immediately: %v %v", actions, strategies)
				}
			case 5:
				if local != 3 || vps != 1 || silent != 4 || localRX != 0 {
					t.Fatal(local, vps, silent, localRX)
				}
			}
			t.Logf("AUTO with optional mode OFF; local opens=%d vps opens=%d first-flight timeouts=%d local RX=%d payload RX=%d", local, vps, silent, localRX, sourceBytes)
		})
	}
}

func TestBrowserAutoLocalBusyDoesNotAuthorizeRelay(t *testing.T) {
	c, cur, q, p := browserAutoLocalFixture(t)
	r := c.browser.youtube
	endpoint := cdnEndpoint{q.Host, p.Destination.String()}
	r.noteEndpointFailure(youtubeScope(cur, q), youTubeLocalDirectCandidate, endpoint, "ORIGIN_SILENT", time.Now())
	for i := 0; i < cap(c.browser.youtubeLocalBetaProbes); i++ {
		c.browser.youtubeLocalBetaProbes <- struct{}{}
	}
	_, _, err := c.openBrowserPlan(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		t.Error("a busy probe slot must not dial either LOCAL or VPS")
		return nil, errors.New("unexpected opener")
	})
	events := r.cdnDecisionSnapshot().Events
	if !errors.Is(err, errBrowserAutoLocalBusy) || len(events) != 1 || events[0].Admission != "PROBE_SLOT_BUSY" || events[0].Phase != "DENIED" {
		t.Fatalf("busy admission: err=%v events=%+v", err, events)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.endpointNegative) != 1 {
		t.Fatalf("slot pressure created a negative endpoint: %+v", r.endpointNegative)
	}
}
