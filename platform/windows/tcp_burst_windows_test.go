//go:build windows

package windowsplatform

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

// Runs on native Windows with real local TCP sockets, mTLS, one-shot tickets,
// QUIC sessions and relay upstream sockets. packetWriter replaces only the
// privileged driver reinjection; this is not external Internet acceptance.
func TestTCPNativeAdmissionBurst(t *testing.T) {
	for _, count := range []int{160, 256} {
		for _, deferred := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/deferred=%t", count, deferred), func(t *testing.T) { testTCPNativeBurst(t, count, deferred) })
		}
	}
}
func testTCPNativeBurst(t *testing.T, count int, deferred bool) {
	b, _ := captureFixture(t)
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	verifier := security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01")
	server, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: verifier, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	pool, err := transport.NewPool(b.ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
		id, _ := security.NewID()
		now := time.Now()
		raw, err := security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "device", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			return nil, err
		}
		return transport.DialWithTicket(ctx, server.Addr().String(), ct, raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	addr, closeEcho, echoStatus, err := burstEchoProcess(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeEcho)
	dst := netip.MustParseAddrPort(addr.String())
	gate := make(chan struct{})
	entered := make(chan struct{}, count)
	b.Engine.SetRelay("VPS-01", pool)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	redirect := &tcpRedirect{b: b, port: uint16(listener.Addr().(*net.TCPAddr).Port), state: newTCPState(8192), admission: newTCPAdmission()}
	cursor := b.evidence.ChangeMarker()
	var injected atomic.Int32
	b.packetWriter = func(p []byte, _ [80]byte) error {
		tuple, _, _, err := ParseTCP(p)
		if err != nil {
			return err
		}
		if tuple.Destination.Port() != redirect.port {
			return fmt.Errorf("protected SYN leaked to destination: %v", tuple)
		}
		injected.Add(1)
		return nil
	}
	apps := make([]net.Conn, count)
	entries := make([]*tcpEntry, count)
	t.Cleanup(func() {
		b.cancel()
		for _, c := range apps {
			if c != nil {
				c.Close()
			}
		}
		redirect.state.mu.Lock()
		for _, e := range entries {
			if e != nil {
				redirect.state.retire(e, time.Now())
			}
		}
		redirect.state.mu.Unlock()
		redirect.wg.Wait()
	})
	// Hold an unrelated already-open relay flow through the entire queued burst.
	warm, err := pool.OpenTCP(b.ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer warm.Close()
	exchange := func(c net.Conn, payload string) error {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte(payload)); err != nil {
			return err
		}
		got := make([]byte, len(payload))
		_, err := io.ReadFull(c, got)
		if err == nil && string(got) != payload {
			return fmt.Errorf("wrong response %q", got)
		}
		return err
	}
	for i := 0; i < count; i++ {
		app, err := net.DialTimeout("tcp4", listener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		local, err := listener.AcceptTCP()
		if err != nil {
			app.Close()
			t.Fatal(err)
		}
		apps[i] = app
		tuple := Tuple{Protocol: "tcp", Source: app.LocalAddr().(*net.TCPAddr).AddrPort(), Destination: dst}
		id := ProcessIdentity{PID: uint32(100 + i%4), CreationTime: 1, Path: fmt.Sprintf("protected-app-%d.exe", i%4)}
		flow := routing.Flow{PID: id.PID, ProcessPath: id.Path, ApplicationID: id.Path, Source: tuple.Source, Destination: dst, PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}}
		decision := Decision{Flow: flow, Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
		mode := "opening"
		if deferred {
			resolved := decision
			resolved.NewConnectionsOnly = true
			resolved.OpenDeferred = func(ctx context.Context, d Decision, reason string) (net.Conn, Decision, error) {
				if reason != "HTTP_HOST" {
					return nil, d, fmt.Errorf("unexpected native origin evidence %s", reason)
				}
				conn, err := b.Engine.OpenTCP(ctx, d.Flow)
				return conn, d, err
			}
			decision.Deferred = true
			decision.ResolveDomain = func(string) Decision { return resolved }
			mode = "relay"
		}
		redirect.state.mu.Lock()
		e := redirect.state.add(tuple, id, decision, "opening", time.Now())
		e.mode = mode
		e.local = local
		e.openDone = make(chan struct{})
		entries[i] = e
		b.evidence.BeginFlow(id, tuple)
		b.evidence.RecordBytes(id, tuple, "captured", "", uint64(len(tcpPacket(t, tuple))))
		b.evidence.RecordPolicy(id, tuple, decision, "")
		if deferred {
			redirect.admitOpen(e, func(release func()) {
				entered <- struct{}{}
				select {
				case <-gate:
				case <-b.ctx.Done():
				}
				redirect.deferredOpen(e, local, release)
			})
		} else {
			syn := tcpPacket(t, tuple)
			redirect.admitOpen(e, func(release func()) {
				entered <- struct{}{}
				select {
				case <-gate:
				case <-b.ctx.Done():
				}
				redirect.open(e, syn, [80]byte{}, release)
			})
		}
		redirect.state.mu.Unlock()
		if deferred {
			app.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err = app.Write([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Deliberately saturate every setup worker, proving 128+ are queued, rather
	// than relying on scheduler speed to happen to reproduce the original bug.
	for i := 0; i < tcpOpenParallel; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("workers did not saturate")
		}
	}
	if len(redirect.admission.pending) != count {
		t.Fatal("queued work disappeared", len(redirect.admission.pending))
	}
	if err := exchange(warm, "established-during-burst"); err != nil {
		t.Fatal("existing flow degraded", err)
	}
	close(gate)
	for i, e := range entries {
		select {
		case <-e.openDone:
		case <-time.After(10 * time.Second):
			t.Fatal("setup stuck", i)
		}
		redirect.state.mu.Lock()
		if e.upstream == nil || e.mode != "relay" {
			mode := e.mode
			redirect.state.mu.Unlock()
			evidence, _ := b.evidence.SnapshotQuery(EvidenceQuery{PID: e.identity.PID, CreationTime: e.identity.CreationTime, Source: e.tuple.Source.String(), Destination: e.tuple.Destination.String()}, nil)
			raw, _ := json.Marshal(evidence)
			t.Fatalf("protected open failed %d mode=%s capture=%s pool=%+v upstream=%+v context=%v echo=%v", i, mode, raw, pool.Snapshot(), server.Metrics.LastUpstreamDialFailure.Load(), b.ctx.Err(), echoStatus())
		}
		if !deferred {
			redirect.wg.Add(1)
			go redirect.pipe(e, e.local, e.upstream)
		}
		redirect.state.mu.Unlock()
		if deferred {
			hello := make([]byte, len("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
			apps[i].SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(apps[i], hello); err != nil {
				t.Fatal("deferred payload", i, err)
			}
		}
	}
	for round := 0; round < 3; round++ {
		for i, c := range apps {
			if err := exchange(c, fmt.Sprintf("socket-%d-round-%d", i, round)); err != nil {
				t.Fatal("socket continuity", i, err)
			}
		}
	}
	if err := exchange(warm, "established-after-burst"); err != nil {
		t.Fatal(err)
	}
	// The ordinary snapshot intentionally returns at most 32 flows. Consume
	// bounded change pages instead, preserving proof for every held connection.
	flows := map[uint64]FlowEvidence{}
	for {
		page, err := b.evidence.ChangePage(ChangeQuery{Cursor: cursor})
		if err != nil || page.EvidenceLost {
			t.Fatal("incomplete evidence", err)
		}
		for _, f := range page.Flows {
			flows[f.FlowID] = f
		}
		cursor = page.Cursor
		if !page.More {
			break
		}
	}
	if len(flows) != count {
		t.Fatal("incomplete flow evidence", len(flows), count)
	}
	for _, f := range flows {
		if f.Route != "RELAY" || f.RequiredBlocked || f.FailureCause != "" || f.Counters.DirectBytes != 0 || f.Counters.Direct != 0 || f.Counters.RelayedBytes == 0 || f.Counters.ReplyBytes == 0 || f.TCPAdmission == nil || f.TCPAdmission.State != "TCP_ADMISSION_READY" {
			t.Fatal("invalid protected evidence", f)
		}
	}
	if !deferred && int(injected.Load()) != count {
		t.Fatal("missing SYN reflections", injected.Load())
	}
	s := pool.Snapshot()
	if s.ActiveFlows != count+1 || s.OpenFailures != 0 || s.ActiveSessions > 8 || s.ProbeReservePerSession != 1 {
		t.Fatal(s)
	}
	t.Logf("native Windows: %d original TCP sockets retained; %d sessions; no DIRECT/no BLOCK", count, s.ActiveSessions)
}

func TestTCPNativeQueuedSetupCancellation(t *testing.T) {
	b, _ := captureFixture(t)
	redirect := &tcpRedirect{b: b, state: newTCPState(16), admission: newTCPAdmission()}
	if err := redirect.admission.slots.Acquire(b.ctx, tcpOpenParallel); err != nil {
		t.Fatal(err)
	}
	defer redirect.admission.slots.Release(tcpOpenParallel)
	tuple := testTuple()
	id := ProcessIdentity{PID: 77, CreationTime: 1, Path: "protected.exe"}
	decision := Decision{BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	redirect.state.mu.Lock()
	e := redirect.state.add(tuple, id, decision, "opening", time.Now())
	e.openDone = make(chan struct{})
	b.evidence.BeginFlow(id, tuple)
	b.evidence.RecordBytes(id, tuple, "captured", "", 40)
	b.evidence.RecordPolicy(id, tuple, decision, "")
	redirect.admitOpen(e, func(release func()) { release(); redirect.wg.Done(); t.Error("cancelled setup executed") })
	// Match policy activation: cancel setup and retire this entry, not other apps.
	e.openCancel()
	e.mode = "hot_attach"
	redirect.state.mu.Unlock()
	select {
	case <-e.openDone:
	case <-time.After(time.Second):
		t.Fatal("queued setup delayed policy activation")
	}
	redirect.wg.Wait()
	f := b.evidence.Snapshot(77).Flows[0]
	if f.RequiredBlocked || f.Counters.DirectBytes != 0 {
		t.Fatal(f)
	}
}

type nativeBlockedWriteRelay struct{ conn net.Conn }

func (r *nativeBlockedWriteRelay) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return r.conn, nil
}
func (r *nativeBlockedWriteRelay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, fmt.Errorf("unused")
}
func TestTCPNativeInitialWriteReleasesAdmission(t *testing.T) {
	b, _ := captureFixture(t)
	app, local := net.Pipe()
	up, target := net.Pipe()
	b.Engine.SetRelay("VPS-01", &nativeBlockedWriteRelay{conn: up})
	redirect := &tcpRedirect{b: b, state: newTCPState(16), admission: newTCPAdmission()}
	t.Cleanup(func() {
		b.cancel()
		app.Close()
		local.Close()
		up.Close()
		target.Close()
		redirect.wg.Wait()
	})
	tuple := testTuple()
	id := ProcessIdentity{PID: 88, CreationTime: 1, Path: "protected.exe"}
	route := routing.Route{RelayID: "VPS-01"}
	resolved := Decision{Flow: routing.Flow{PID: 88, ProcessPath: id.Path, ApplicationID: "protected", Source: tuple.Source, Destination: tuple.Destination, PinnedPolicy: &routing.Policy{Route: route, BlockOnFailure: true}}, Route: route, BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	d := resolved
	d.Deferred = true
	d.ResolveDomain = func(string) Decision { return resolved }
	redirect.state.mu.Lock()
	e := redirect.state.add(tuple, id, d, "opening", time.Now())
	e.mode = "relay"
	e.local = local
	e.openDone = make(chan struct{})
	b.evidence.BeginFlow(id, tuple)
	b.evidence.RecordBytes(id, tuple, "captured", "", 40)
	b.evidence.RecordPolicy(id, tuple, d, "")
	redirect.admitOpen(e, func(release func()) { redirect.deferredOpen(e, local, release) })
	redirect.state.mu.Unlock()
	if err := app.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Write([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.openDone:
	case <-time.After(time.Second):
		t.Fatal("first blocked upstream write retained setup")
	}
	if len(redirect.admission.pending) != 0 || !redirect.admission.slots.TryAcquire(tcpOpenParallel) {
		t.Fatal("established write retained opening permit")
	}
	redirect.admission.slots.Release(tcpOpenParallel)
	// target intentionally never reads: application backpressure stays on this
	// socket, rather than exhausting admission for unrelated new connections.
}

// Isolated destination fixture. Its accept/error counters diagnose target
// failure separately from client admission and authenticated pool capacity.
func burstTCPEcho() (net.Addr, func(), func() string, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, nil, err
	}
	var accepted atomic.Int32
	var acceptFailure atomic.Pointer[string]
	var wg sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	closed := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					message := err.Error()
					acceptFailure.Store(&message)
				}
				return
			}
			accepted.Add(1)
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			conns[conn] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() { conn.Close(); mu.Lock(); delete(conns, conn); mu.Unlock() }()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr(), func() {
			listener.Close()
			mu.Lock()
			closed = true
			for c := range conns {
				c.Close()
			}
			mu.Unlock()
			wg.Wait()
		}, func() string {
			failure := ""
			if v := acceptFailure.Load(); v != nil {
				failure = *v
			}
			health, err := net.DialTimeout("tcp4", listener.Addr().String(), 500*time.Millisecond)
			if health != nil {
				health.Close()
			}
			return fmt.Sprintf("accepted=%d accept_error=%q probe_error=%v", accepted.Load(), failure, err)
		}, nil
}

// A real external destination does not share the client service's socket table
// or Go poller. Keep the target in a separate, bounded child process while every
// 160/256 protected connection still targets ONE listener and stays open.
func burstEchoProcess(t *testing.T) (net.Addr, func(), func() string, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd := exec.Command(exe, "-test.run=^TestTCPNativeBurstEchoChild$", "-test.v=false")
	cmd.Env = append(os.Environ(), "NEEXITLAG_BURST_ECHO_CHILD=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, nil, nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		in.Close()
		return nil, nil, nil, err
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			in.Close()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("echo child: %v: %s", err, stderr.String())
				}
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Error("echo child shutdown timed out")
			}
			if text := strings.TrimSpace(stderr.String()); text != "" {
				t.Log("destination child:", text)
			}
		})
	}
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	var address string
	select {
	case address = <-ready:
	case <-time.After(5 * time.Second):
		stop()
		return nil, nil, nil, fmt.Errorf("echo child readiness timeout")
	}
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil || addr.Port == 0 {
		stop()
		return nil, nil, nil, fmt.Errorf("invalid echo child greeting %q", address)
	}
	status := func() string {
		counts := map[uint32]int{}
		rows, tableErr := queryOwnedTCP()
		for _, row := range rows {
			if row.PID == uint32(cmd.Process.Pid) && row.Tuple.Source.Port() == uint16(addr.Port) {
				counts[row.State]++
			}
		}
		probe, probeErr := net.DialTimeout("tcp4", addr.String(), 500*time.Millisecond)
		if probe != nil {
			probe.Close()
		}
		return fmt.Sprintf("child_pid=%d TCP_states=%v table_error=%v probe_error=%v", cmd.Process.Pid, counts, tableErr, probeErr)
	}
	return addr, stop, status, nil
}
func TestTCPNativeBurstEchoChild(t *testing.T) {
	if os.Getenv("NEEXITLAG_BURST_ECHO_CHILD") != "1" {
		t.Skip("dedicated destination child")
	}
	addr, stop, status, err := burstTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	fmt.Println(addr.String())
	io.Copy(io.Discard, os.Stdin)
	fmt.Fprintln(os.Stderr, status())
}
