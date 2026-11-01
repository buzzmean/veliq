//go:build windows

package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

// A copied test executable supplies an actual Windows PID/birth/path, not a
// Chromium process or an owner-lookup stub. It never opens a browser or policy.
func TestCDNColdOwnerProcess(t *testing.T) {
	if os.Getenv("VELIQ_TEST_CDN_OWNER_CHILD") != "1" {
		t.Skip("isolated owner subprocess")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func cdnColdOwner(t *testing.T) wp.ProcessIdentity {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "chrome.exe")
	if err := os.WriteFile(path, raw, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=^TestCDNColdOwnerProcess$")
	cmd.Env = append(os.Environ(), "VELIQ_TEST_CDN_OWNER_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	id, err := wp.NewDiscovery().Lookup(uint32(cmd.Process.Pid))
	if err != nil || !wp.IsCurrent(id) {
		t.Fatal("actual owner identity", err)
	}
	return id
}

type cdnColdTuple struct{ source, destination netip.AddrPort }

type cdnColdBackend struct {
	nativeBackendFixture
	owner                       wp.ProcessIdentity
	publicAddress, mediaAddress string
	mu                          sync.Mutex
	committed                   map[cdnColdTuple]bool
	mediaOpens                  atomic.Int32
}

func (b *cdnColdBackend) OpenBrowserLocalTCP(ctx context.Context, owner wp.ProcessIdentity, source, destination netip.AddrPort, d wp.Decision) (net.Conn, error) {
	if owner.PID != b.owner.PID || owner.CreationTime != b.owner.CreationTime || owner.Path != b.owner.Path || !wp.IsCurrent(owner) || !d.Route.Local() || d.Local == nil || d.LocalStrategyID == "" {
		return nil, errors.New("fixture requires live owner and a compiled LOCAL decision")
	}
	address := b.publicAddress
	if youtubeCDN(youtubeKey{Domain: youtubeSubgroup(d.OriginDomain)}) {
		address = b.mediaAddress
		b.mediaOpens.Add(1)
	} else if d.OriginDomain != "www.youtube.com" {
		return nil, errors.New("unexpected fixture origin")
	}
	conn, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	return &cdnColdWriteWitness{Conn: conn, backend: b, tuple: cdnColdTuple{source, destination}}, nil
}

func (b *cdnColdBackend) BrowserTransformApplied(owner wp.ProcessIdentity, source, destination netip.AddrPort) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return owner.PID == b.owner.PID && owner.CreationTime == b.owner.CreationTime && owner.Path == b.owner.Path && b.committed[cdnColdTuple{source, destination}]
}

type cdnColdWriteWitness struct {
	net.Conn
	backend *cdnColdBackend
	tuple   cdnColdTuple
}

func (c *cdnColdWriteWitness) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		// Explicit transform seam: this fixture does not inject WinDivert
		// packets. Witnesses still belong to the exact opened socket tuple.
		c.backend.mu.Lock()
		c.backend.committed[c.tuple] = true
		c.backend.mu.Unlock()
	}
	return n, err
}

// Only destination mapping is synthetic; the forwarded stream uses real
// QUIC+mTLS, a one-shot ticket and a relay egress distinguishable at the origin.
type cdnColdRelay struct {
	pool              *transport.Pool
	logical, physical netip.AddrPort
	opens             atomic.Int32
}

func (r *cdnColdRelay) OpenTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if dst != r.logical {
		return nil, errors.New("unexpected fixture relay destination")
	}
	r.opens.Add(1)
	return r.pool.OpenTCP(ctx, r.physical)
}
func (*cdnColdRelay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, errors.New("no datagrams in CDN TLS fixture")
}

func cdnColdRelayPool(t *testing.T, ctx context.Context) *transport.Pool {
	t.Helper()
	serverTLS, clientTLS, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: serverTLS, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"fixture": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: time.Minute, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	peer := clientTLS.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	pool, err := transport.NewPool(ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
		id, err := security.NewID()
		if err != nil {
			return nil, err
		}
		now := time.Now()
		ticket, err := security.Sign("ticket", "fixture", private, security.Ticket{ID: id, DeviceID: "cdn-cold-fixture", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			return nil, err
		}
		return transport.DialWithTicket(ctx, s.Addr().String(), clientTLS, ticket)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// Real service path: cold RELAY HTTP bytes -> asynchronous public TLS/403 ->
// guarded LOCAL trial -> running strong promotion -> peer LOCAL. No counters,
// qualifications or trial outcomes are manually seeded. DNS/IP mapping and the
// packet-transform witness are seams; this is not Chrome playback/driver/ISP.
func TestWindowsCDNColdFlowThroughBackgroundAndLocalPromotion(t *testing.T) {
	owner := cdnColdOwner(t)
	for _, hint := range []bool{false, true} {
		t.Run(map[bool]string{false: "SNI", true: "DNS-hint"}[hint], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			var publicRequests atomic.Int32
			public, publicRoots := youtubeTLSHTTPFixture(t, "www.youtube.com", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				publicRequests.Add(1)
				http.Error(w, "public fixture is not a media segment", http.StatusForbidden)
			}))
			const chunkSize = 128 * 1024
			media, mediaRoots := youtubeTLSHTTPFixture(t, "*.googlevideo.com", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				source, _, _ := net.SplitHostPort(request.RemoteAddr)
				w.Header().Set("X-Fixture-Egress", source)
				w.Header().Set("Content-Length", strconv.Itoa(12*chunkSize))
				chunk := bytes.Repeat([]byte("v"), chunkSize)
				for i := 0; i < 12; i++ {
					if request.URL.Path == "/sustained" && i > 0 {
						select {
						case <-request.Context().Done():
							return
						case <-time.After(320 * time.Millisecond):
						}
					}
					if _, err := w.Write(chunk); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			c := New(ctx)
			t.Cleanup(c.Close)
			c.enabled, c.settings.Automatic = true, true
			c.BrowserProbeRoots = publicRoots
			profile := profiles.Profile{ID: "cdn-cold", Name: "CDN cold owner fixture", Executables: []string{owner.Path}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}
			if err := c.Profiles.Upsert(profile); err != nil {
				t.Fatal(err)
			}
			c.network.Store(&wp.NetworkContext{Fingerprint: "cdn-cold-net", ObservedAt: time.Now(), ConflictsObservedAt: time.Now()})
			logical := netip.MustParseAddrPort("74.125.111.131:443")
			c.BrowserAlternativeDNS = func(_ context.Context, host string, _ browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
				if host != "www.youtube.com" {
					return browserproxy.DNSAnswer{}, errors.New("unexpected fixture DNS name")
				}
				return browserproxy.DNSAnswer{Addresses: []netip.Addr{logical.Addr()}, TTL: time.Minute, ObtainedAt: time.Now(), Source: "ISOLATED_FIXTURE"}, nil
			}
			backend := &cdnColdBackend{owner: owner, publicAddress: public.Listener.Addr().String(), mediaAddress: media.Listener.Addr().String(), committed: map[cdnColdTuple]bool{}}
			c.Backend = backend
			forwarder := &cdnColdRelay{pool: cdnColdRelayPool(t, ctx), logical: logical, physical: media.Listener.Addr().(*net.TCPAddr).AddrPort()}
			c.Engine.SetRelay("VPS-01", forwarder)
			q := browserproxy.Request{Owner: browserproxy.Owner{PID: owner.PID, Birth: owner.CreationTime, Exe: owner.Path, Profile: profile.ID}, Source: netip.MustParseAddrPort("127.0.0.1:50101"), Host: "rr1---sn-cold.googlevideo.com", Port: 443, Secure: true, HintOnly: hint}
			cur, err := c.browserProfile(q.Owner)
			if err != nil || !cur.enabled {
				t.Fatal("owner/profile validation", err)
			}
			p := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: logical, Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: youtubeLadderSource}}
			open := func(request browserproxy.Request, want flowpolicy.Action) (*tls.Conn, net.Conn) {
				t.Helper()
				conn, actual, err := c.openBrowserPlan(ctx, cur, request, p, c.browserOpen)
				if err != nil {
					t.Fatal("open service plan", err)
				}
				t.Cleanup(func() { conn.Close() })
				if actual.Policy.Action != want {
					t.Fatalf("route = %+v, want %s", actual.Policy, want)
				}
				secure := tls.Client(conn, &tls.Config{RootCAs: mediaRoots, ServerName: request.Host, MinVersion: tls.VersionTLS12})
				secure.SetDeadline(time.Now().Add(10 * time.Second))
				if err := secure.HandshakeContext(ctx); err != nil {
					t.Fatal("verified media TLS", err)
				}
				return secure, conn
			}
			relayTLS, pinned := open(q, flowpolicy.RelayRequired)
			cdnColdRequest(t, relayTLS, q.Host, "/initial", "127.0.0.2", 12*chunkSize)
			c.browser.youtube.workers.Wait()
			r := c.browser.youtube
			s := r.snapshot()
			if publicRequests.Load() != 1 || s.Selection.BackgroundFailures != 1 || s.Selection.Trials != 0 {
				t.Fatalf("cold public 403 path: requests=%d selection=%+v", publicRequests.Load(), s.Selection)
			}
			q.Source = netip.MustParseAddrPort("127.0.0.1:50102")
			localTLS, _ := open(q, flowpolicy.DirectPlus)
			cdnColdRequest(t, localTLS, q.Host, "/sustained", "127.0.0.1", 12*chunkSize)
			s = r.snapshot()
			if s.Selection.Trials != 1 || s.Selection.StrongPromotions != 1 || s.Selection.ActiveTrial || s.Selection.PeerProofs != 1 {
				t.Fatalf("no running promotion from actual media bytes: %+v", s.Selection)
			}
			q.Host, q.Source = "rr2---sn-peer.googlevideo.com", netip.MustParseAddrPort("127.0.0.1:50103")
			peerTLS, _ := open(q, flowpolicy.DirectPlus)
			cdnColdRequest(t, peerTLS, q.Host, "/peer", "127.0.0.1", 12*chunkSize)
			// The original TLS connection still sends on the original relay;
			// neither LOCAL promotion nor a different subgroup can migrate it.
			cdnColdRequest(t, relayTLS, "rr1---sn-cold.googlevideo.com", "/pinned", "127.0.0.2", 12*chunkSize)
			if policy, ok := pinned.(interface {
				CurrentTCPPolicy() (flowpolicy.Result, bool)
			}); !ok {
				t.Fatal("missing pinned plan reporter")
			} else if got, known := policy.CurrentTCPPolicy(); !known || got.Action != flowpolicy.RelayRequired {
				t.Fatal("established relay route changed", got)
			}
			if forwarder.opens.Load() != 1 || backend.mediaOpens.Load() != 2 || r.snapshot().Selection.PeerProvisional != 1 {
				t.Fatal("unexpected extra route opens", forwarder.opens.Load(), backend.mediaOpens.Load(), r.snapshot().Selection)
			}
			var localRX, relayRX uint64
			for _, stage := range r.snapshot().Stages {
				if stage.Stage == "LOCAL" {
					localRX += stage.RX
				} else if stage.Stage == "RELAY" {
					relayRX += stage.RX
				}
			}
			if localRX < 24*chunkSize || relayRX < 24*chunkSize {
				t.Fatal("actual TLS bytes missing from route accounting", localRX, relayRX)
			}
			t.Logf("public_403=1 relay_opens=1 local_media_opens=2 strong_promotions=1 peer_provisional=1 pinned_relay_preserved=true local_rx=%d relay_rx=%d", localRX, relayRX)
			q.Owner.Birth++
			if conn, err := c.browserOpenUnobserved(ctx, q, p); err == nil {
				conn.Close()
				t.Fatal("reused owner identity accepted")
			}
		})
	}
}

func cdnColdRequest(t *testing.T, conn *tls.Conn, host, path, source string, bytesWant int) {
	t.Helper()
	req, err := http.NewRequest("GET", "https://"+host+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Fixture-Egress") != source || !bytes.Equal(body, bytes.Repeat([]byte("v"), bytesWant)) {
		t.Fatalf("media body/route: status=%d source=%s bytes=%d err=%v", response.StatusCode, response.Header.Get("X-Fixture-Egress"), len(body), err)
	}
}
