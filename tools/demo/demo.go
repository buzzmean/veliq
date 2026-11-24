// Package demo runs the actual core and multiple authenticated local relays without interception.
package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/veliq/core/ipc"
	"github.com/buzzmean/veliq/core/measurement"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	clientservice "github.com/buzzmean/veliq/services/client-service"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/echo"
	"github.com/buzzmean/veliq/tools/labcert"
	"github.com/buzzmean/veliq/tools/networklab"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

//go:embed frontend.html
var assets embed.FS

type Lab struct {
	Controller *clientservice.Controller
	Token      string
	RPC        *ipc.Server
	relays     map[string]*relay.Server
	clients    []*transport.Client
	paths      []*networklab.Path
	mu         sync.Mutex
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	stopTCP    func()
}

func New(parent context.Context) (*Lab, error) {
	ctx, cancel := context.WithCancel(parent)
	c := clientservice.New(ctx)
	c.Demo = true
	c.Selector = optimizer.New(optimizer.Parameters{MinimumImprovement: 5, MinimumLifetime: 4 * time.Second, ConfirmationPeriod: 2 * time.Second, MaxAge: 15 * time.Second})
	c.Measurements = measurement.New(measurement.Settings{ActiveInterval: time.Second, IdleInterval: 10 * time.Second, Timeout: 150 * time.Millisecond, Spacing: 20 * time.Millisecond, Samples: 3, Concurrency: 3})
	c.Measurements.OnFailure = c.Selector.ReportProbeFailure
	token, e := security.NewID()
	if e != nil {
		cancel()
		return nil, e
	}
	lab := &Lab{Controller: c, Token: token, relays: make(map[string]*relay.Server), cancel: cancel}
	fail := func(e error) (*Lab, error) { lab.Close(); return nil, e }
	s, t, e := labcert.Pair()
	if e != nil {
		return fail(e)
	}
	pub, issuer, _ := ed25519.GenerateKey(rand.Reader)
	peer := t.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	direct, e := networklab.Start(45*time.Millisecond, 5)
	if e != nil {
		return fail(e)
	}
	lab.paths = append(lab.paths, direct)
	candidates := []measurement.Candidate{{Metadata: optimizer.RelayCandidate{ID: optimizer.Direct}, Target: netip.MustParseAddrPort(direct.Addr().String()), Open: measurement.OpenDirect}}
	for i, id := range []string{"FRA-01", "WAW-01", "HEL-01"} {
		path, e := networklab.Start(time.Duration(5+5*i)*time.Millisecond, 0)
		if e != nil {
			return fail(e)
		}
		lab.paths = append(lab.paths, path)
		verifier := security.NewTicketVerifier(map[string]ed25519.PublicKey{"lab": pub}, id)
		server, e := relay.Listen("127.0.0.1:0", relay.Config{TLS: s, TicketVerifier: verifier, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
		if e != nil {
			return fail(e)
		}
		lab.relays[id] = server
		now := time.Now()
		nonce, _ := security.NewID()
		raw, e := security.Sign("ticket", "lab", issuer, security.Ticket{ID: nonce, DeviceID: "local-demo", DeviceKey: security.Fingerprint(peer), RelayID: id, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)})
		if e != nil {
			return fail(e)
		}
		attempt, stop := context.WithTimeout(ctx, 3*time.Second)
		client, e := transport.DialWithTicket(attempt, server.Addr().String(), t, raw)
		stop()
		if e != nil {
			return fail(e)
		}
		lab.clients = append(lab.clients, client)
		c.Engine.SetRelay(id, client)
		candidates = append(candidates, measurement.Candidate{Metadata: optimizer.RelayCandidate{ID: id, Address: server.Addr().String()}, Target: netip.MustParseAddrPort(path.Addr().String()), Open: client.OpenDatagram})
	}
	c.Measurements.SetCandidates(candidates)
	c.FailRelay = func(id string) error {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		server := lab.relays[id]
		if server == nil {
			return errors.New("unknown local relay")
		}
		server.Close()
		return nil
	}
	tcp, stopTCP, e := echo.TCP()
	if e != nil {
		return fail(e)
	}
	lab.stopTCP = stopTCP
	c.TCPDiagnosticTarget = tcp.String()
	rpc, e := ipc.New(token, c.Handle)
	if e != nil {
		return fail(e)
	}
	lab.RPC = rpc
	c.Handle(ctx, "optimize", json.RawMessage(`{"enabled":true}`))
	c.Start()
	lab.wg.Add(1)
	go func() {
		defer lab.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		seq := uint16(40000)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				seq++
				if seq == 0 {
					seq = 40000
				}
				snapshot := c.Snapshot()
				if !snapshot.Optimizing {
					continue
				}
				flow := routing.Flow{Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), seq), Destination: netip.MustParseAddrPort(lab.paths[1].Addr().String()), PID: 123, ProcessPath: "local-demo.exe", ApplicationID: "cs2"}
				attempt, stop := context.WithTimeout(ctx, 300*time.Millisecond)
				d, e := c.Engine.OpenUDP(attempt, flow)
				if e == nil {
					payload := []byte("neexitlag real demo flow")
					if d.Send(payload) == nil {
						c.RecordTraffic("cs2", 0, uint64(len(payload)))
						if b, e := d.Receive(attempt); e == nil {
							c.RecordTraffic("cs2", uint64(len(b)), 0)
						}
					}
					d.Close()
				}
				stop()
			}
		}
	}()
	return lab, nil
}
func (l *Lab) Close() {
	l.cancel()
	l.Controller.Close()
	l.wg.Wait()
	for _, client := range l.clients {
		client.Close()
	}
	for _, server := range l.relays {
		server.Close()
	}
	for _, path := range l.paths {
		path.Close()
	}
	if l.stopTCP != nil {
		l.stopTCP()
	}
}
func (l *Lab) Handler(address string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, e := net.SplitHostPort(r.Host)
		_, expectedPort, _ := net.SplitHostPort(address)
		if e != nil || port != expectedPort || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
			http.Error(w, "invalid local host", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			b, _ := assets.ReadFile("frontend.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(strings.ReplaceAll(string(b), "__IPC_TOKEN__", l.Token)))
		case r.Method == "GET" && r.URL.Path == "/metrics":
			l.Metrics().ServeHTTP(w, r)
		case r.Method == "POST" && r.URL.Path == "/api/ipc":
			media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if media != "application/json" {
				http.Error(w, "JSON required", 415)
				return
			}
			raw, e := io.ReadAll(io.LimitReader(r.Body, ipc.MaxMessage+1))
			var q ipc.Request
			if e != nil || security.Parse(raw, &q) != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			reply := l.RPC.Execute(ctx, q, time.Now())
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(reply)
		default:
			http.NotFound(w, r)
		}
	})
}
func (l *Lab) Metrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snapshot := l.Controller.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for _, route := range snapshot.Routes {
			fmt.Fprintf(w, "neexitlag_probe_latency_seconds{route=%q} %g\nneexitlag_relay_health{route=%q} %d\n", route.ID, route.RTTMS/1000, route.ID, boolInt(route.Status == "healthy"))
		}
	})
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
