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
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func enableDPILocalFixture(t *testing.T) {
	t.Helper()
	old := BrowserDPILocalField
	BrowserDPILocalField = "pc24"
	t.Cleanup(func() { BrowserDPILocalField = old })
}

func TestDPILocalOnlyColdTimeoutAndWarmTLS(t *testing.T) {
	enableDPILocalFixture(t)
	for _, host := range []string{"rr1---sn-test.googlevideo.com", "discord.com"} {
		t.Run(host, func(t *testing.T) {
			c, cur, q, p := youtubeFixture(t)
			q.Host, q.Ingress = host, "PAC_CONNECT"
			c.Backend = &youtubeTransformFixture{}
			const responseBytes = 2 * 1024 * 1024
			body := bytes.Repeat([]byte("v"), responseBytes)
			server, roots := youtubeTLSHTTPFixture(t, host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			}))
			r := c.browser.youtube
			var opens []string
			open := func(ctx context.Context, request browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
				if plan.Policy.Action != flowpolicy.DirectPlus || plan.Policy.RelayID != "" || request.Host != host || plan.Destination != p.Destination {
					t.Errorf("unexpected upstream plan: %+v", plan)
					return nil, errors.New("forbidden fixture route")
				}
				opens = append(opens, plan.Policy.Strategy)
				if len(opens) == 1 {
					a, b := net.Pipe()
					go func() {
						defer b.Close()
						_, _ = io.Copy(io.Discard, b)
					}()
					return a, nil
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			exchange := func() {
				t.Helper()
				raw, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				secure := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
				if err := secure.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequest(http.MethodGet, "https://"+host+"/video-fixture", nil)
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
				rx, err := io.Copy(io.Discard, resp.Body)
				if err != nil || resp.StatusCode != http.StatusOK || rx != responseBytes {
					t.Fatalf("TLS/HTTP response: status=%d bytes=%d err=%v", resp.StatusCode, rx, err)
				}
			}
			exchange()
			first := r.cdnDecisionSnapshot().Events
			if len(opens) != 2 || opens[0] == opens[1] || len(first) != 4 ||
				first[0].Reason != "COLD_LOCAL_PROBE" || first[2].Phase != "FAILED" || first[2].Reason != "ORIGIN_SILENT" ||
				first[3].Phase != "OPENED" || first[3].Stage != "LOCAL" || first[3].ConnectionID != first[0].ConnectionID {
				t.Fatalf("cold attempt sequence: %+v", first)
			}
			exchange()
			all := r.cdnDecisionSnapshot().Events
			if len(opens) != 3 || opens[2] != opens[1] || len(all) != 6 || all[4].Reason != "LEARNED_LOCAL" ||
				all[4].Strategy != first[3].Strategy || all[5].Stage != "LOCAL" {
				t.Fatalf("warm connection did not immediately use confirmed strategy: %+v", all)
			}
			for _, event := range all {
				if event.Stage == "RELAY" {
					t.Fatal("unexpected relay in local-only events")
				}
			}
			s := r.snapshot()
			records := 0
			for _, rec := range s.Records {
				if rec.Domain == host && rec.Stage == "LOCAL" && rec.RX >= responseBytes {
					records++
				}
			}
			if records != 2 {
				t.Fatalf("expected two sustained LOCAL records, got %d", records)
			}
			t.Logf("%s first failure=%s; warm strategy=%s; successful LOCAL bodies=%d bytes; relay opens=0", host, first[2].Reason, all[4].Strategy, responseBytes)
		})
	}
}

func TestDPILocalOnlyExhaustedAndGuarded(t *testing.T) {
	enableDPILocalFixture(t)
	c, cur, q, p := youtubeFixture(t)
	q.Ingress = "PAC_CONNECT"
	var opens int
	open := func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		opens++
		if plan.Policy.Action != flowpolicy.DirectPlus || plan.Policy.RelayID != "" {
			t.Errorf("unexpected upstream policy: %+v", plan.Policy)
		}
		return nil, errors.New("controlled open failure")
	}
	_, blocked, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
	if err == nil || opens != browserDPILocalAttempts || blocked.Policy.Action != flowpolicy.Block || blocked.Policy.Reason != "DPI_LOCAL_CANDIDATES_EXHAUSTED" {
		t.Fatalf("expected bounded failure: opens=%d plan=%+v err=%v", opens, blocked.Policy, err)
	}
	for _, test := range []struct {
		network, ingress, want string
	}{
		{cur.network, "NATIVE_TCP", "DPI_LOCAL_CONNECT_AUTHORITY_REQUIRED"},
		{"different-network", "PAC_CONNECT", "DPI_LOCAL_NETWORK_GUARD"},
	} {
		now := cur
		now.network, q.Ingress = test.network, test.ingress
		_, blocked, err = c.openBrowserPlan(context.Background(), now, q, p, open)
		if err == nil || blocked.Policy.Reason != test.want || opens != browserDPILocalAttempts {
			t.Fatalf("wanted %s without additional opens, got %+v error=%v", test.want, blocked.Policy, err)
		}
	}
	q.Ingress = "PAC_CONNECT"
	cur.profile.Rules = []flowpolicy.Rule{{ID: "relay", Protocol: "tcp", Domains: []string{q.Host}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}
	_, blocked, err = c.openBrowserPlan(context.Background(), cur, q, p, open)
	if err == nil || blocked.Policy.Reason != "DPI_LOCAL_EXPLICIT_RELAY_RULE" || opens != browserDPILocalAttempts {
		t.Fatalf("explicit relay rule did not fail closed: %+v %v", blocked.Policy, err)
	}
}

func TestDPILocalOnlyDNSAndProtectedScope(t *testing.T) {
	enableDPILocalFixture(t)
	c, cur, q, p := youtubeFixture(t)
	for _, host := range []string{"www.youtube.com", "youtubei.googleapis.com", "rr1---sn-test.googlevideo.com", "discord.com"} {
		if !c.browserDPILocalOrigin(host) {
			t.Fatalf("missing local DPI scope: %s", host)
		}
	}
	for _, host := range []string{"chatgpt.com", "gemini.google.com", "claude.ai", "google.com", "dns.google"} {
		if c.browserDPILocalOrigin(host) {
			t.Fatalf("unrelated or protected origin in local DPI scope: %s", host)
		}
	}
	addr, err := dpiLocalDNS(context.Background(), q.Host, func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip4" || host != q.Host {
			t.Fatalf("wrong DNS request: %s %s", network, host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), p.Destination.Addr()}, nil
	})
	if err != nil || addr != p.Destination.Addr() {
		t.Fatalf("local DNS selection: %s %v", addr, err)
	}
	_, err = dpiLocalDNS(context.Background(), q.Host, func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	if !errors.Is(err, browserproxy.ErrOriginDNS) {
		t.Fatalf("expected unusable local DNS result, got %v", err)
	}
	for _, host := range []string{"www.youtube.com", "youtubei.googleapis.com", "rr1---sn-test.googlevideo.com", "discord.com"} {
		t.Run(host, func(t *testing.T) {
			query, reply := brokerWire(t, host)
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go func() {
				buf := make([]byte, 8192)
				if _, peer, err := server.ReadFrom(buf); err == nil {
					_, _ = server.WriteTo(reply, peer)
				}
			}()
			tuple := policyTuple("udp", 53)
			tuple.Destination = server.LocalAddr().(*net.UDPAddr).AddrPort()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			out, err := c.exchangeBrowserDNS(ctx, cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
				t.Error("local DPI DNS attempted relay")
				return nil, errors.New("unexpected relay")
			})
			if err != nil || !bytes.Equal(out, reply) {
				t.Fatalf("local DNS transaction failed: %v", err)
			}
		})
	}
	doh, ok := dpiLocalDoHPolicy("dns.google", netip.MustParseAddrPort("8.8.8.8:443"))
	if !ok || doh.Action != flowpolicy.Direct || doh.RelayID != "" || doh.Fallback != flowpolicy.FailBlock {
		t.Fatalf("known Secure DNS should retain the named endpoint locally: %+v", doh)
	}
	unknown, ok := dpiLocalDoHPolicy("", netip.MustParseAddrPort("8.8.8.8:443"))
	if !ok || unknown.Action != flowpolicy.Block {
		t.Fatalf("opaque Secure DNS must fail closed: %+v", unknown)
	}
	if reason := (&updater{}).disabled(); reason != "DPI_LOCAL_FIELD_TEST" {
		t.Fatalf("field build could update during measurement: %s", reason)
	}
	q.Host = "chatgpt.com"
	p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}
	called := false
	open := func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		called = true
		if plan.Policy.Action != flowpolicy.RelayRequired {
			t.Errorf("protected policy changed: %+v", plan.Policy)
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	conn, _, err := c.openBrowserPlan(context.Background(), cur, q, p, open)
	if err != nil || !called {
		t.Fatalf("protected policy was not exercised: %v", err)
	}
	conn.Close()
}
