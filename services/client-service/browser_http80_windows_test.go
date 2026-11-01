//go:build windows

package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

type http80Tuple struct{ source, destination netip.AddrPort }
type http80Backend struct {
	nativeBackendFixture
	owner         wp.ProcessIdentity
	address       string
	mu            sync.Mutex
	committed     map[http80Tuple]bool
	noWitness     bool
	opens, splits atomic.Int32
}

func (b *http80Backend) OpenBrowserLocalTCP(ctx context.Context, owner wp.ProcessIdentity, source, destination netip.AddrPort, d wp.Decision) (net.Conn, error) {
	if owner.PID != b.owner.PID || owner.CreationTime != b.owner.CreationTime || owner.Path != b.owner.Path || !wp.IsCurrent(owner) || destination != netip.MustParseAddrPort("74.125.111.131:80") || d.OriginDomain != "www.youtube.com" || !d.Route.Local() || d.Local == nil {
		return nil, errors.New("HTTP80 fixture scope")
	}
	conn, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}).DialContext(ctx, "tcp4", b.address)
	if err != nil {
		return nil, err
	}
	b.opens.Add(1)
	x := &http80Socket{Conn: conn, backend: b, key: http80Tuple{source, destination}, engine: d.Local, meta: localstrategy.Metadata{Application: owner.Path, Domain: d.OriginDomain, Protocol: "tcp", StrategyID: d.LocalStrategyID, Destination: destination}, sequence: 1000}
	syn := x.packet(nil, 999)
	syn[33] = 2
	x.engine.Process(syn, &x.state, x.meta)
	x.state.ConfirmHandshake(1000, 99)
	return x, nil
}
func (b *http80Backend) BrowserTransformApplied(owner wp.ProcessIdentity, source, destination netip.AddrPort) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return owner.PID == b.owner.PID && owner.CreationTime == b.owner.CreationTime && owner.Path == b.owner.Path && !b.noWitness && b.committed[http80Tuple{source, destination}]
}

// Packet capture/injection is a seam: the actual engine transforms synthetic
// IPv4/TCP inputs, then its unchanged payload bytes traverse real loopback TCP.
type http80Socket struct {
	net.Conn
	backend  *http80Backend
	key      http80Tuple
	engine   *localstrategy.LocalStrategyEngine
	meta     localstrategy.Metadata
	mu       sync.Mutex
	state    localstrategy.State
	buffer   localstrategy.HelloBuffer
	sequence uint32
}

func (x *http80Socket) packet(data []byte, seq uint32) []byte {
	p := make([]byte, 40+len(data))
	p[0] = 0x45
	p[8] = 64
	p[9] = 6
	p[6] = 0x40
	p[32] = 0x50
	p[33] = 0x18
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], []byte{192, 0, 2, 1})
	ip := x.meta.Destination.Addr().As4()
	copy(p[16:20], ip[:])
	binary.BigEndian.PutUint16(p[20:], x.key.source.Port())
	binary.BigEndian.PutUint16(p[22:], 80)
	binary.BigEndian.PutUint32(p[24:], seq)
	binary.BigEndian.PutUint32(p[28:], 100)
	copy(p[40:], data)
	return p
}
func (x *http80Socket) Write(data []byte) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	p := x.packet(data, x.sequence)
	x.sequence += uint32(len(data))
	accepted, out := x.engine.BufferTCP(p, &x.state, &x.buffer, x.meta, time.Now())
	if accepted && out == nil {
		return len(data), nil
	}
	var result localstrategy.Result
	packets := [][]byte{p}
	if out != nil {
		result = out.Result
		packets = out.Originals
	} else {
		result = x.engine.Process(p, &x.state, x.meta)
	}
	if result.Modified {
		packets = result.Packets
	}
	for _, packet := range packets {
		payload := packet[20+int(packet[32]>>4)*4:]
		if _, err := io.Copy(x.Conn, bytes.NewReader(payload)); err != nil {
			return 0, err
		}
	}
	if result.Modified {
		x.backend.splits.Add(1)
		x.backend.mu.Lock()
		x.backend.committed[x.key] = true
		x.backend.mu.Unlock()
	}
	return len(data), nil
}
func (x *http80Socket) Close() error {
	x.backend.mu.Lock()
	delete(x.backend.committed, x.key)
	x.backend.mu.Unlock()
	return x.Conn.Close()
}

type http80Relay struct {
	pool        *transport.Pool
	destination netip.AddrPort
	opens       atomic.Int32
}

func (r *http80Relay) OpenTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if dst != netip.MustParseAddrPort("74.125.111.131:80") {
		return nil, errors.New("HTTP80 relay fixture scope")
	}
	r.opens.Add(1)
	return r.pool.OpenTCP(ctx, r.destination)
}
func (*http80Relay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, errors.New("no datagrams")
}

func waitHTTP80(t *testing.T, c *Controller) {
	t.Helper()
	done := make(chan struct{})
	go func() { c.browser.http80.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("HTTP80 worker stuck")
	}
	if c.browser.http80.snapshot().Active || len(c.browser.probes) != 0 {
		t.Fatal("probe capacity leaked")
	}
}
func requestHTTP80(t *testing.T, conn net.Conn, path, source string) {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://www.youtube.com"+path, bytes.NewBufferString("fixture-body"))
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "fixture-body" || resp.Header.Get("X-Fixture-Egress") != source {
		t.Fatal("HTTP bytes/route", resp.StatusCode, string(body), resp.Header.Get("X-Fixture-Egress"), err)
	}
}

func TestWindowsHTTP80ColdUpgradeAndFailure(t *testing.T) {
	owner := http80Owner(t)
	for _, variant := range []string{"upgrade", "missing-witness", "foreign-redirect", "block-page", "cancel-off", "cancel-network"} {
		t.Run(variant, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			resume := func() { releaseOnce.Do(func() { close(release) }) }
			defer resume()
			reset, resetDone := make(chan struct{}), make(chan struct{})
			var resetOnce sync.Once
			doReset := func() { resetOnce.Do(func() { close(reset) }) }
			defer doReset()
			var heads, posts, resets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				source, _, _ := net.SplitHostPort(r.RemoteAddr)
				w.Header().Set("X-Fixture-Egress", source)
				if r.Method == "HEAD" {
					n := heads.Add(1)
					if r.URL.Path != "/" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
						t.Error("probe inherited user request")
					}
					if n == 1 && (variant == "cancel-off" || variant == "cancel-network") {
						close(entered)
						select {
						case <-release:
						case <-r.Context().Done():
							return
						}
					}
					if variant == "block-page" {
						w.WriteHeader(200)
						return
					}
					target := "https://www.youtube.com/"
					if variant == "foreign-redirect" {
						target = "https://other.example/"
					}
					w.Header().Set("Location", target)
					w.WriteHeader(301)
					return
				}
				if r.URL.Path == "/reset" {
					resets.Add(1)
					w.Header().Set("Content-Length", "131072")
					w.Write(bytes.Repeat([]byte("r"), 65536))
					w.(http.Flusher).Flush()
					select {
					case <-reset:
					case <-r.Context().Done():
						return
					}
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					raw := conn.(*net.TCPConn)
					raw.SetLinger(0)
					raw.Close()
					close(resetDone)
					return
				}
				posts.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.Write(body)
			}))
			t.Cleanup(server.Close)
			c := New(ctx)
			t.Cleanup(c.Close)
			c.customPath = filepath.Join(t.TempDir(), "profiles.json")
			c.enabled = true
			c.settings.Automatic = true
			profile := profiles.Profile{ID: "http80-fixture", Name: "HTTP80 owner", Executables: []string{owner.Path}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}
			if err := c.Profiles.Upsert(profile); err != nil {
				t.Fatal(err)
			}
			setNetwork := func(name string) {
				c.network.Store(&wp.NetworkContext{Fingerprint: name, ObservedAt: time.Now(), ConflictsObservedAt: time.Now()})
			}
			setNetwork("http80-net")
			backend := &http80Backend{owner: owner, address: server.Listener.Addr().String(), committed: map[http80Tuple]bool{}, noWitness: variant == "missing-witness"}
			backend.ready, backend.id = true, owner
			c.Backend = backend
			forwarder := &http80Relay{pool: http80RelayPool(t, ctx), destination: server.Listener.Addr().(*net.TCPAddr).AddrPort()}
			c.Engine.SetRelay("VPS-01", forwarder)
			q := browserproxy.Request{Owner: browserproxy.Owner{PID: owner.PID, Birth: owner.CreationTime, Exe: owner.Path, Profile: profile.ID}, Source: netip.MustParseAddrPort("127.0.0.1:50101"), Host: "www.youtube.com", Port: 80, Ingress: "NATIVE_TCP"}
			cur, err := c.browserProfile(q.Owner)
			if err != nil {
				t.Fatal(err)
			}
			p := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: netip.MustParseAddrPort("74.125.111.131:80"), Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: youtubeLadderSource}}
			open := func(want flowpolicy.Action) net.Conn {
				t.Helper()
				cur, err := c.browserProfile(q.Owner)
				if err != nil {
					t.Fatal(err)
				}
				conn, actual, err := c.openBrowserPlan(ctx, cur, q, p, c.browserOpen)
				if err != nil {
					t.Fatal(err)
				}
				if actual.Policy.Action != want {
					conn.Close()
					t.Fatal("route", actual)
				}
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				t.Cleanup(func() { conn.Close() })
				return conn
			}
			original := open(flowpolicy.RelayRequired)
			requestHTTP80(t, original, "/cold", "127.0.0.2")
			if variant == "cancel-off" || variant == "cancel-network" {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("probe did not enter")
				}
				if variant == "cancel-off" {
					if _, err := c.Handle(ctx, "optimize", []byte(`{"enabled":false}`)); err != nil {
						t.Fatal(err)
					}
				} else {
					setNetwork("other-net")
				}
				resume()
				waitHTTP80(t, c)
				s := c.browser.http80.snapshot()
				if s.Upgrades != 0 || s.Cancelled != 1 || s.Failures != 0 {
					t.Fatal("stale HTTP result published", s)
				}
				if variant == "cancel-off" {
					if _, err := c.Handle(ctx, "optimize", []byte(`{"enabled":true}`)); err != nil {
						t.Fatal(err)
					}
				} else {
					setNetwork("http80-net")
				}
				q.Source = netip.MustParseAddrPort("127.0.0.1:50102")
				requestHTTP80(t, open(flowpolicy.RelayRequired), "/resumed-cold", "127.0.0.2")
			}
			waitHTTP80(t, c)
			good := variant == "upgrade" || variant == "cancel-off" || variant == "cancel-network"
			q.Source = netip.MustParseAddrPort("127.0.0.1:50103")
			want, source := flowpolicy.RelayRequired, "127.0.0.2"
			if good {
				want, source = flowpolicy.DirectPlus, "127.0.0.1"
			}
			warm := open(want)
			requestHTTP80(t, warm, "/warm", source)
			waitHTTP80(t, c)
			if good {
				if c.browser.http80.snapshot().Upgrades != 1 || backend.splits.Load() < 2 {
					t.Fatal("LOCAL lacks actual engine transform")
				}
				relayBefore := forwarder.opens.Load()
				req, _ := http.NewRequest("GET", "http://www.youtube.com/reset", nil)
				if err := req.Write(warm); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(warm), req)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(response.Body, make([]byte, 32768)); err != nil {
					t.Fatal(err)
				}
				doReset()
				_, err = io.ReadAll(response.Body)
				response.Body.Close()
				if !errors.Is(err, syscall.Errno(10054)) {
					t.Fatal("not native TCP reset", err)
				}
				<-resetDone
				if resets.Load() != 1 || forwarder.opens.Load() != relayBefore || c.browser.http80.snapshot().Failures != 1 {
					t.Fatal("reset replayed or lost failure", c.browser.http80.snapshot())
				}
				q.Source = netip.MustParseAddrPort("127.0.0.1:50104")
				requestHTTP80(t, open(flowpolicy.RelayRequired), "/after-reset", "127.0.0.2")
				waitHTTP80(t, c)
				if forwarder.opens.Load() != relayBefore+1 || c.browser.http80.snapshot().Upgrades != 1 {
					t.Fatal("reset retried before cooldown")
				}
			} else if c.browser.http80.snapshot().Upgrades != 0 || backend.opens.Load() != 1 {
				t.Fatal("unproven HTTP used LOCAL", c.browser.http80.snapshot())
			}
			requestHTTP80(t, original, "/pinned", "127.0.0.2")
			if len(c.browser.youtube.qualifications) != 0 || c.browser.youtube.snapshot().Selection.Trials != 0 {
				t.Fatal("HTTP proof leaked into TLS/CDN")
			}
			t.Logf("variant=%s real_owner=true packet_engine_splits=%d HTTP80=%+v relay_opens=%d no_request_replay=true old_relay_preserved=true", variant, backend.splits.Load(), c.browser.http80.snapshot(), forwarder.opens.Load())
		})
	}
}

// The owner is a copied test exe with a real Windows PID/birth/path, not Chrome.
func TestHTTP80OwnerProcess(t *testing.T) {
	if os.Getenv("VELIQ_TEST_HTTP80_OWNER_CHILD") != "1" {
		t.Skip("isolated owner subprocess")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func http80Owner(t *testing.T) wp.ProcessIdentity {
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
	cmd := exec.Command(path, "-test.run=^TestHTTP80OwnerProcess$")
	cmd.Env = append(os.Environ(), "VELIQ_TEST_HTTP80_OWNER_CHILD=1")
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

func http80RelayPool(t *testing.T, ctx context.Context) *transport.Pool {
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
		ticket, err := security.Sign("ticket", "fixture", private, security.Ticket{ID: id, DeviceID: "http80-fixture", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
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
