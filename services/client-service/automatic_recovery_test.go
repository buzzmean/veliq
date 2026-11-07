package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

var automaticRecoveryChanges = []string{"network", "network-stale", "network-error", "disabled", "automatic-off", "failover", "local-revision", "profile-direct", "profile-rule", "unrelated-profile"}

func changeAutomaticRecoveryScope(t *testing.T, c *Controller, cur profilesResult, change string) {
	t.Helper()
	switch change {
	case "network", "network-stale", "network-error":
		n := *c.network.Load()
		switch change {
		case "network":
			n.Fingerprint = "replacement-network"
		case "network-stale":
			n.ObservedAt = time.Now().Add(-time.Minute)
		case "network-error":
			n.Error = "unavailable"
		}
		c.network.Store(&n)
	case "disabled", "automatic-off", "failover":
		c.mu.Lock()
		if change == "disabled" {
			c.enabled = false
		} else if change == "automatic-off" {
			c.settings.Automatic = false
		} else {
			c.settings.Failover += "-changed"
		}
		c.mu.Unlock()
	case "local-revision":
		config := localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "new-local", Name: "New local", Version: 1, Application: cur.id.Path, Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"93.184.216.0/24"}, Cutoff: 2, Strategy: "tcp-split-1", Enabled: true}}}
		if err := c.Local.Reload(config); err != nil {
			t.Fatal(err)
		}
	case "profile-direct", "profile-rule", "unrelated-profile":
		p := cur.profile
		switch change {
		case "profile-direct":
			p.Mode = profiles.Direct
		case "profile-rule":
			p.Rules = []flowpolicy.Rule{{ID: "new-block", Domains: []string{"ordinary.example.org"}, Action: flowpolicy.Block}}
		case "unrelated-profile":
			p.ID, p.Name, p.Executables = "other-app", "Other app", []string{`C:\Other\other.exe`}
		}
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown scope change", change)
	}
}

func awaitAutomaticRecovery(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery fixture did not reach barrier")
	}
}

func TestAutomaticRecoveryRejectsDialFailureAfterScopeChange(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, change := range automaticRecoveryChanges {
			t.Run(fmt.Sprintf("tls=%v/%s", secure, change), func(t *testing.T) {
				c, cur, q, p := automaticFixture(t)
				if !secure {
					q.Host, q.Port, q.Secure = "", 5222, false
					p.Destination = netip.AddrPortFrom(p.Destination.Addr(), q.Port)
				}
				p.DirectCandidates = []netip.AddrPort{p.Destination, netip.MustParseAddrPort("93.184.216.35:443")}
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				var result error
				go func() {
					defer close(done)
					_, _, result = c.openAutomaticPlan(context.Background(), cur, q, p, func(_ context.Context, request browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
						if calls.Add(1) == 1 {
							close(entered)
							<-release
							// The production browserOpen path records this result before
							// the outer automatic opener can examine it. Exercise that
							// ordering too, so an outer-only guard cannot pass this test.
							c.observeDirectOpen(cur, request, actual, context.DeadlineExceeded, time.Now())
							return nil, context.DeadlineExceeded
						}
						return nil, errors.New("fixture ends recovery here")
					})
				}()
				awaitAutomaticRecovery(t, entered)
				changeAutomaticRecoveryScope(t, c, cur, change)
				close(release)
				awaitAutomaticRecovery(t, done)
				key := c.directTimeoutKey(cur, q, p)
				if !secure {
					key.Host = p.Destination.Addr().String()
				}
				learned := c.browser.directTimeouts.AddressFailed(key, time.Now())
				if change == "unrelated-profile" {
					if !learned || calls.Load() < 2 {
						t.Fatal("unrelated edit disabled valid recovery", learned, calls.Load(), result)
					}
					return
				}
				if learned || calls.Load() != 1 || result == nil || c.browser.directTimeouts.Stats().ActiveAddresses != 0 {
					t.Fatalf("stale dial learned/retried: learned=%v calls=%d result=%v stats=%+v", learned, calls.Load(), result, c.browser.directTimeouts.Stats())
				}
			})
		}
	}
}

func TestAutomaticRecoveryRejectsDelayedFirstFlightAfterScopeChange(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		for _, change := range automaticRecoveryChanges[:len(automaticRecoveryChanges)-1] {
			t.Run(fmt.Sprintf("ordinary=%v/%s", ordinary, change), func(t *testing.T) {
				c, cur, q, p := automaticFixture(t)
				p.DirectCandidates = []netip.AddrPort{p.Destination, netip.MustParseAddrPort("93.184.216.35:443")}
				a, peer := net.Pipe()
				defer peer.Close()
				var calls atomic.Int32
				opener := func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
					if calls.Add(1) == 1 {
						return a, nil
					}
					return nil, errors.New("fixture forbids a retry after scope change")
				}
				var raw net.Conn
				var err error
				if ordinary {
					raw, _, err = c.openOrdinaryAddresses(context.Background(), cur, q, p, opener)
				} else {
					raw, _, err = c.openAutomaticPlan(context.Background(), cur, q, p, opener)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				client := tls.Client(raw, &tls.Config{ServerName: q.Host, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
				client.SetDeadline(time.Now().Add(3 * time.Second))
				done := make(chan struct{})
				var handshakeErr error
				go func() { defer close(done); handshakeErr = client.Handshake() }()
				// Read the real TLS client's complete first record before changing
				// scope; no callback is invoked directly and no payload is replayed.
				peer.SetReadDeadline(time.Now().Add(3 * time.Second))
				var header [5]byte
				if _, err := io.ReadFull(peer, header[:]); err != nil {
					t.Fatal(err)
				}
				if header[0] != 22 {
					t.Fatal("expected TLS ClientHello record")
				}
				if _, err := io.CopyN(io.Discard, peer, int64(binary.BigEndian.Uint16(header[3:]))); err != nil {
					t.Fatal(err)
				}
				changeAutomaticRecoveryScope(t, c, cur, change)
				peer.Close()
				awaitAutomaticRecovery(t, done)
				key := c.directTimeoutKey(cur, q, p)
				if c.browser.directTimeouts.AddressFailed(key, time.Now()) || calls.Load() != 1 || handshakeErr == nil || c.browser.directTimeouts.Stats().ActiveAddresses != 0 {
					t.Fatalf("late first-flight failure learned/retried: calls=%d err=%v stats=%+v", calls.Load(), handshakeErr, c.browser.directTimeouts.Stats())
				}
			})
		}
	}
}

// A dial can finish successfully after AUTO was disabled. The resulting socket
// must be closed before the caller can send any application bytes on that route.
func TestAutomaticRecoveryClosesLateSuccessfulOpen(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			c, cur, q, p := automaticFixture(t)
			q.Secure = secure
			a, peer := net.Pipe()
			defer peer.Close()
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var result net.Conn
			var resultErr error
			go func() {
				defer close(done)
				result, _, resultErr = c.openAutomaticPlan(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
					close(entered)
					<-release
					return a, nil
				})
			}()
			awaitAutomaticRecovery(t, entered)
			changeAutomaticRecoveryScope(t, c, cur, "automatic-off")
			close(release)
			awaitAutomaticRecovery(t, done)
			if result != nil || !errors.Is(resultErr, errAutomaticScopeChanged) {
				t.Fatalf("late socket exposed: %v %v", result, resultErr)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			var payload [1]byte
			if n, err := peer.Read(payload[:]); n != 0 || err != io.EOF {
				t.Fatal("late socket not closed before payload", n, err)
			}
		})
	}
}

func TestAutomaticRecoveryInvalidCachedScopeDoesNotResolveOrOpen(t *testing.T) {
	for _, viaOrdinary := range []bool{false, true} {
		t.Run(fmt.Sprint(viaOrdinary), func(t *testing.T) {
			c, cur, q, p := automaticFixture(t)
			key := c.directTimeoutKey(cur, q, p)
			c.browser.directTimeouts.RecordTimeout(key, time.Now())
			var dns, opens atomic.Int32
			c.BrowserResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
				dns.Add(1)
				return nil, errors.New("unexpected DNS")
			}}
			changeAutomaticRecoveryScope(t, c, cur, "failover")
			opener := func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
				opens.Add(1)
				return nil, errors.New("unexpected OPEN")
			}
			var err error
			if viaOrdinary {
				_, _, err = c.openOrdinaryAddresses(context.Background(), cur, q, p, opener)
			} else {
				_, _, err = c.openAutomaticPlan(context.Background(), cur, q, p, opener)
			}
			if !errors.Is(err, errAutomaticScopeChanged) || dns.Load() != 0 || opens.Load() != 0 {
				t.Fatal("stale cached scope performed work", err, dns.Load(), opens.Load())
			}
			if stats := c.browser.directTimeouts.Stats(); stats.ActiveAddresses != 1 || stats.ActiveOrigins != 0 {
				t.Fatal("old evidence was changed", stats)
			}
		})
	}
}

func TestAutomaticRecoverySecondAddressFailureDoesNotPromoteStaleOrigin(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	peer := netip.MustParseAddrPort("93.184.216.35:443")
	p.DirectCandidates = []netip.AddrPort{p.Destination, peer}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var result error
	go func() {
		defer close(done)
		_, _, result = c.openAutomaticPlan(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
			if calls.Add(1) == 2 {
				close(entered)
				<-release
			}
			return nil, context.DeadlineExceeded
		})
	}()
	awaitAutomaticRecovery(t, entered)
	changeAutomaticRecoveryScope(t, c, cur, "network")
	close(release)
	awaitAutomaticRecovery(t, done)
	stats := c.browser.directTimeouts.Stats()
	if !errors.Is(result, errAutomaticScopeChanged) || calls.Load() != 2 || stats.ActiveAddresses != 1 || stats.ActiveOrigins != 0 {
		t.Fatal("stale second address promoted origin or started ladder", result, calls.Load(), stats)
	}
	if !c.directAddressFailed(cur, q, p) || c.directAddressFailed(cur, q, browserproxy.RetargetOrigin(p, peer)) {
		t.Fatal("first valid failure lost or second stale failure learned")
	}
}

func TestAutomaticRecoveryGuardReachesSharedTransportBeforeCompatibility(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	changeAutomaticRecoveryScope(t, c, cur, "automatic-off")
	ctx := context.WithValue(context.Background(), automaticScopeKey{}, cur)
	// The stale recovery marker must fail before owner/platform resolution or
	// the legacy cached-PAC compatibility branch can select an unplanned DIRECT.
	conn, err := c.browserOpen(ctx, q, p)
	if conn != nil || !errors.Is(err, errAutomaticScopeChanged) {
		t.Fatal("automatic recovery lost its scope at shared transport", conn, err)
	}
}

func TestAutomaticRecoveryLeavesEstablishedPayloadPinned(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	q.Host, q.Port, q.Secure = "", 5222, false
	p.Destination = netip.AddrPortFrom(p.Destination.Addr(), q.Port)
	a, peer := net.Pipe()
	defer peer.Close()
	var calls atomic.Int32
	conn, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		calls.Add(1)
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	changeAutomaticRecoveryScope(t, c, cur, "failover")
	conn.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("one non-idempotent message")
	done := make(chan struct{})
	var writeErr error
	go func() { defer close(done); _, writeErr = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != string(payload) {
		t.Fatal("established stream was disturbed", string(got), err)
	}
	awaitAutomaticRecovery(t, done)
	if writeErr != nil || calls.Load() != 1 {
		t.Fatal("established stream was retried", writeErr, calls.Load())
	}
}

func TestAutomaticRecoveryStopsAfterScopeChangesDuringDNS(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	var once sync.Once
	var dns, opens atomic.Int32
	c.BrowserResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dns.Add(1)
		once.Do(func() { changeAutomaticRecoveryScope(t, c, cur, "automatic-off") })
		return nil, errors.New("DNS fixture ends here")
	}}
	_, _, err := c.openOrdinaryAddresses(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		opens.Add(1)
		return nil, errors.New("unexpected OPEN")
	})
	if !errors.Is(err, errAutomaticScopeChanged) || dns.Load() == 0 || opens.Load() != 0 || c.browser.directTimeouts.Stats().ActiveAddresses != 0 {
		t.Fatal("work continued after DNS invalidated scope", err, dns.Load(), opens.Load())
	}
}

func TestAutomaticRecoveryLadderDoesNotLearnStaleLocalFailure(t *testing.T) {
	for _, firstFlight := range []bool{false, true} {
		t.Run(fmt.Sprint(firstFlight), func(t *testing.T) {
			c, cur, q, p := automaticFixture(t)
			// Fresh LOCAL proof for the same endpoint, without a background probe.
			q.Source = netip.AddrPort{}
			r := c.browser.youtube
			key := youtubeScope(cur, q)
			r.confirmed(key, "LOCAL", youtubeLegacyOrder[0], time.Now())
			r.mu.Lock()
			before := r.cache[key]
			r.mu.Unlock()
			var calls atomic.Int32
			a, peer := net.Pipe()
			defer a.Close()
			defer peer.Close()
			opener := func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
				calls.Add(1)
				if firstFlight {
					return a, nil
				}
				changeAutomaticRecoveryScope(t, c, cur, "automatic-off")
				return nil, context.DeadlineExceeded
			}
			raw, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, opener)
			if firstFlight {
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				client := tls.Client(raw, &tls.Config{ServerName: q.Host, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
				client.SetDeadline(time.Now().Add(3 * time.Second))
				done := make(chan struct{})
				go func() { defer close(done); _ = client.Handshake() }()
				peer.SetReadDeadline(time.Now().Add(3 * time.Second))
				var header [5]byte
				if _, e := io.ReadFull(peer, header[:]); e != nil {
					t.Fatal(e)
				}
				if _, e := io.CopyN(io.Discard, peer, int64(binary.BigEndian.Uint16(header[3:]))); e != nil {
					t.Fatal(e)
				}
				changeAutomaticRecoveryScope(t, c, cur, "automatic-off")
				peer.Close()
				awaitAutomaticRecovery(t, done)
			} else if !errors.Is(err, errAutomaticScopeChanged) {
				t.Fatal(err)
			}
			r.mu.Lock()
			after := r.cache[key]
			r.mu.Unlock()
			if calls.Load() != 1 || after.Stage != before.Stage || after.Reason != before.Reason || !after.Until.Equal(before.Until) || after.Tried != before.Tried {
				t.Fatalf("stale LOCAL failure changed learning: opens=%d before=%+v after=%+v", calls.Load(), before, after)
			}
		})
	}
}

func TestAutomaticRecoveryLateLocalResponseKeepsPayloadWithoutRenewingProof(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	q.Source = netip.AddrPort{}
	c.Backend = &youtubeTransformFixture{}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	payload := bytes.Repeat([]byte("one-response-"), 12000)
	server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write(payload)
	}))
	r := c.browser.youtube
	key := youtubeScope(cur, q)
	r.confirmed(key, "LOCAL", youtubeLegacyOrder[0], time.Now())
	r.mu.Lock()
	before := r.cache[key]
	r.mu.Unlock()
	var calls atomic.Int32
	raw, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(ctx context.Context, _ browserproxy.Request, _ browserproxy.Plan) (net.Conn, error) {
		calls.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var body []byte
	var exchangeErr error
	go func() {
		defer close(done)
		client := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
		client.SetDeadline(time.Now().Add(5 * time.Second))
		if exchangeErr = client.Handshake(); exchangeErr != nil {
			return
		}
		req, _ := http.NewRequest("GET", "https://"+q.Host+"/", nil)
		if exchangeErr = req.Write(client); exchangeErr != nil {
			return
		}
		var response *http.Response
		response, exchangeErr = http.ReadResponse(bufio.NewReader(client), req)
		if exchangeErr != nil {
			return
		}
		defer response.Body.Close()
		body, exchangeErr = io.ReadAll(response.Body)
	}()
	awaitAutomaticRecovery(t, entered)
	changeAutomaticRecoveryScope(t, c, cur, "failover")
	close(release)
	awaitAutomaticRecovery(t, done)
	r.mu.Lock()
	after := r.cache[key]
	r.mu.Unlock()
	if exchangeErr != nil || !bytes.Equal(body, payload) || calls.Load() != 1 {
		t.Fatal("scope change disturbed established payload", exchangeErr, len(body), calls.Load())
	}
	if !after.Until.Equal(before.Until) || after.VerifiedBytes != before.VerifiedBytes || after.Reason != before.Reason {
		t.Fatalf("late response renewed obsolete LOCAL proof: before=%+v after=%+v", before, after)
	}
}
