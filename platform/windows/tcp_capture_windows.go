//go:build windows

package windowsplatform

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/routing"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type delegatedTCP struct {
	owner    *tcpEntry
	decision Decision
}
type nativeTCPTraceHook struct {
	f func(string, Tuple, byte, byte)
}
type tcpRedirect struct {
	fixtureTrace atomic.Pointer[nativeTCPTraceHook]
	delegatedMu  sync.Mutex
	delegated    map[Tuple]delegatedTCP
	b            *WinDivertBackend
	handle       uintptr
	listener     *net.TCPListener
	port         uint16
	state        *tcpState
	admission    *tcpAdmission
	wg           sync.WaitGroup
}

func (b *WinDivertBackend) startTCP(d *divertDLL) (*tcpRedirect, error) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	// Inbound physical connections to the internal listener are dropped. Reflected
	// packets injected below this handle are the only admitted listener traffic.
	filter := nativeTCPNetworkFilter(port, b.testBrowserLoopback)
	b.ingress.mu.Lock()
	b.ingress.tcpFilter = filter
	b.ingress.mu.Unlock()
	h, err := d.openHandle(filter, 0, 0)
	if err != nil {
		l.Close()
		return nil, err
	}
	d.setParam.Call(h, 0, 2048)
	d.setParam.Call(h, 1, 100)
	d.setParam.Call(h, 2, 4*1024*1024)
	return &tcpRedirect{b: b, handle: h, listener: l, port: port, state: newTCPState(8192), delegated: map[Tuple]delegatedTCP{}, admission: newTCPAdmission()}, nil
}
func (t *tcpRedirect) start(classify Classifier) {
	t.wg.Add(3)
	go t.packets(classify)
	go t.accept()
	go t.cleanup()
}
func (t *tcpRedirect) stop() {
	t.listener.Close()
	t.b.proc().shutdown.Call(t.handle, 1)
	t.state.mu.Lock()
	for _, e := range t.state.entries {
		if err := e.localBuffer.Flush(e.decision, &e.localState, e.identity, e.tuple, time.Now(), "NO_TRANSFORM", t.b.evidence); err != nil {
			t.b.fail(err)
		}
		if e.upstream != nil {
			e.upstream.Close()
		}
		if e.local != nil {
			e.local.Close()
		}
	}
	t.state.mu.Unlock()
	t.wg.Wait()
	// Shutdown(RECV) may drain queued captures after the first flush. With all
	// producers stopped, release any late ClientHello before closing SEND.
	t.state.mu.Lock()
	for _, e := range t.state.entries {
		if err := e.localBuffer.Flush(e.decision, &e.localState, e.identity, e.tuple, time.Now(), "NO_TRANSFORM", t.b.evidence); err != nil {
			t.b.fail(err)
		}
	}
	t.state.mu.Unlock()
	t.b.proc().close.Call(t.handle)
}
func (t *tcpRedirect) send(p []byte, a [80]byte) error {
	if t.b.packetWriter != nil {
		return t.b.packetWriter(p, a)
	}
	d := t.b.proc()
	d.checksum.Call(uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(&a[0])), 0)
	var n uint32
	ok, _, err := d.send.Call(t.handle, uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&a[0])))
	if ok == 0 {
		return fmt.Errorf("TCP reinjection: %w", err)
	}
	if n != uint32(len(p)) {
		return fmt.Errorf("TCP reinjection short packet: %d/%d", n, len(p))
	}
	return nil
}
func (t *tcpRedirect) record(e *tcpEntry, event string, n int) {
	t.b.evidence.RecordBytes(e.identity, e.tuple, event, e.decision.Route.RelayID, uint64(n))
}
func (t *tcpRedirect) reflect(e *tcpEntry, p []byte, a [80]byte, reply bool) error {
	source, destination := netip.AddrPortFrom(e.tuple.Destination.Addr(), e.virtual), netip.AddrPortFrom(e.tuple.Source.Addr(), t.port)
	if reply {
		source, destination = e.tuple.Destination, e.tuple.Source
	}
	out, err := ReflectTCP(p, source, destination)
	if err != nil {
		return err
	}
	a[10] &= ^byte(2) // inbound
	err = t.send(out, a)
	if err == nil {
		tuple, flags, _, _ := ParseTCP(out)
		t.traceFixture("inject_ok", tuple, flags, a[10])
	}
	if err == nil {
		event := "captured_proxy"
		if !e.decision.Deferred {
			event = "relay"
			if reply {
				event = "reply"
			}
			if e.decision.Route.Direct() {
				event = "direct_proxy"
			}
		}
		t.record(e, event, 0)
	}
	return err
}
func (t *tcpRedirect) packets(classify Classifier) {
	defer t.wg.Done()
	d := t.b.proc()
	buf := make([]byte, 65535)
	for {
		var n uint32
		var a [80]byte
		ok, _, err := d.recv.Call(t.handle, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&a[0])))
		if ok == 0 {
			if t.b.ctx.Err() == nil {
				t.b.fail(fmt.Errorf("TCP capture receive: %w", err))
			}
			return
		}
		if n == 0 || n > uint32(len(buf)) {
			continue
		}
		t.processPacket(buf[:n], a, classify)
	}
}
func (t *tcpRedirect) processPacket(p []byte, a [80]byte, classify Classifier) {
	t.b.ingress.tcp.Add(1)
	t.b.policyMu.RLock()
	defer t.b.policyMu.RUnlock()

	tuple, flags, _, err := ParseTCP(p)
	if err != nil {
		if err = t.send(p, a); err != nil && t.b.ctx.Err() == nil {
			t.b.fail(err)
		}
		return
	}
	t.traceFixture("capture", tuple, flags, a[10])
	// The isolated Chrome acceptance enables loopback packet observation only.
	// Pass every unrelated loopback packet unchanged; only exact delegated
	// upstream tuples enter the production transform path.
	if t.b.testBrowserLoopback && a[10]&4 != 0 {
		t.delegatedMu.Lock()
		_, forward := t.delegated[tuple]
		_, reverse := t.delegated[Tuple{Protocol: "tcp", Source: tuple.Destination, Destination: tuple.Source}]
		t.delegatedMu.Unlock()
		// The native fixture also redirects a delegated socket into this
		// listener. Its exact virtual reply must reach reflect(), not be
		// reinjected with the listener source port. Unrelated loopback stays out.
		t.state.mu.Lock()
		entry := t.state.ports[tuple.Destination.Port()]
		reflectedReply := entry != nil && tuple.Source.Port() == t.port && tuple.Source.Addr() == entry.tuple.Source.Addr() && tuple.Destination.Addr() == entry.tuple.Destination.Addr()
		t.state.mu.Unlock()
		if !forward && !reflectedReply {
			if reverse && flags&0x3f == 0x12 {
				t.state.mu.Lock()
				if entry := t.state.entries[Tuple{Protocol: "tcp", Source: tuple.Destination, Destination: tuple.Source}]; entry != nil {
					entry.localState.ConfirmHandshake(binary.BigEndian.Uint32(p[28:]), binary.BigEndian.Uint32(p[24:]))
					entry.localState.ObserveServerTTL(p[8])
				}
				t.state.mu.Unlock()
			}
			_ = t.send(p, a)
			return
		}
	}
	// External traffic to the interception listener is never admitted.
	// Native SYN/ACK observation shares this handle; it is reinjected
	// unchanged and only confirms an exact existing DIRECT+ handshake.
	if a[10]&2 == 0 {
		if tuple.Destination.Port() != t.port {
			reverse := Tuple{Protocol: "tcp", Source: tuple.Destination, Destination: tuple.Source}
			if t.blockNativeInbound(reverse, classify) {
				t.b.hotBlocked()
				return
			}
			t.state.mu.Lock()
			if e := t.state.entries[reverse]; e != nil && e.mode == "direct" && e.decision.Route.Local() {
				t.b.evidence.RecordLocalTCPPacket(e.identity, e.tuple, p, true)
				if p[0] == 0x45 && flags&0x3f == 0x12 && 20+int(p[32]>>4)*4 == len(p) {
					e.localState.ConfirmHandshake(binary.BigEndian.Uint32(p[28:]), binary.BigEndian.Uint32(p[24:]))
					e.localState.ObserveServerTTL(p[8])
				}
			}
			t.state.mu.Unlock()
			if err = t.send(p, a); err != nil && t.b.ctx.Err() == nil {
				t.b.fail(err)
			}
		}
		return
	}
	t.state.mu.Lock()
	// Service listener responses have an exact mapping; do not trust a port alone.
	e := t.state.ports[tuple.Destination.Port()]
	if tuple.Source.Port() == t.port && e != nil && tuple.Source.Addr() == e.tuple.Source.Addr() && tuple.Destination.Addr() == e.tuple.Destination.Addr() {
		e.last = time.Now()
		err = t.reflect(e, p, a, true)
		t.state.mu.Unlock()
		if err != nil && t.b.ctx.Err() == nil {
			t.b.fail(err)
		}
		return
	}
	sequence := binary.BigEndian.Uint32(p[int(p[0]&15)*4+4:])
	if old := t.state.entries[tuple]; old != nil && flags&0x12 == 2 && sequence != old.initialSequence {
		if flushErr := old.localBuffer.Flush(old.decision, &old.localState, old.identity, old.tuple, time.Now(), "NO_TRANSFORM", t.b.evidence); flushErr != nil {
			t.b.fail(flushErr)
		}
	}
	e = t.state.existing(tuple, flags, sequence, time.Now())
	if e != nil {
		e.last = time.Now()
		t.record(e, "captured", len(p))
		if e.domainInspections < 8 && p[0] == 0x45 {
			e.domainInspections++
			h := 20 + int(p[32]>>4)*4
			if h <= len(p) {
				t.b.evidence.RecordDomain(e.identity, e.tuple, localstrategy.PacketDomain(p[h:]))
			}
		}
		epoch := t.b.policyEpoch.Load()
		if e.hotEpoch != epoch && e.mode != "hot_attach" && e.mode != "closed" {
			latest := classify(e.identity, e.tuple)
			if latest.Revision != e.decision.Revision && needsHotAttach(latest) {
				t.state.retire(e, time.Now())
				e.mode = "hot_attach"
				e.decision = latest
				t.b.evidence.RecordLifecycle(e.identity, e.tuple, "HOT_ATTACH_RETIRED")
				t.b.evidence.BeginFlow(e.identity, e.tuple)
				t.b.evidence.RecordPolicy(e.identity, e.tuple, latest, "")
				t.b.evidence.RecordHotAttach(e.identity, e.tuple, t.b.hot.snapshot().Epoch, "HOT_ATTACH_PREEXISTING", latest.Revision)
			}
			e.hotEpoch = epoch
		}
		mode := e.mode
		if mode == "relay" {
			err = t.reflect(e, p, a, false)
		} else if mode == "direct" {
			if e.decision.Route.Local() {
				t.b.evidence.RecordLocalTCPPacket(e.identity, e.tuple, p, false)
			}
			err = e.localBuffer.Push(e.decision, &e.localState, e.identity, e.tuple, p, func(q []byte) error { return t.send(q, a) }, t.b.evidence, time.Now())
		} else if mode == "hot_attach" && lanGameOwnsTCP(e.identity, tuple) {
			err = t.send(p, a)
		} else if mode == "hot_attach" {
			t.b.hotBlocked()
			t.b.Drops.Add(1)
			t.b.evidence.RecordDrop(e.identity, e.tuple, "HOT_ATTACH_PENDING", false)
			t.resetFromPacket(p, a)
		} else if mode == "block" || mode == "closed" {
			t.b.Drops.Add(1)
			t.b.evidence.RecordDrop(e.identity, e.tuple, tcpPacketDropCause(mode), mode == "block")
		}
		t.state.mu.Unlock()
		if err != nil && t.b.ctx.Err() == nil {
			t.b.fail(err)
		}
		return
	}
	t.state.mu.Unlock()
	// Capture only new SYNs. Midstream packets never acquire a new route.
	id := ProcessIdentity{}
	t.b.associations.mu.RLock()
	association, known := t.b.associations.items[tuple]
	t.b.associations.mu.RUnlock()
	// A live cached process does not prove that it still owns this tuple:
	// Windows reuses ephemeral ports while the old process is still running.
	// Query the exact native TCP owner first, especially for service-created
	// DIRECT/CONNECT sockets; stale Chrome associations must never recurse.
	pid, ownerErr := resolveTCPOwner(tuple)
	ownerSource, ownerCode := "TCP_OWNER_TABLE", ""
	if ownerErr == nil {
		var lookupErr error
		id, lookupErr = t.b.cache.Lookup(pid)
		if lookupErr != nil {
			ownerCode = "PROCESS_LOOKUP_FAILED"
			id.PID = pid
		}
	} else if known && IsCurrent(association.Identity) {
		id = association.Identity
		ownerSource = "SOCKET_OR_FLOW_ASSOCIATION"
	}
	if ownerErr != nil {
		t.b.ingress.unknown.Add(1)
		ownerCode = ownerErr.Error()
	}
	decision, self := ClassifyCapture(id, tuple, uint32(os.Getpid()), classify)
	t.delegatedMu.Lock()
	delegated, owned := t.delegated[tuple]
	t.delegatedMu.Unlock()
	if owned {
		// Port reservation can race an unrelated bind. Only the service's actual
		// socket may consume an internal delegation, never another process using
		// the same tuple during the bounded reservation/bind interval.
		pid, ownerErr := resolveTCPOwner(tuple)
		if delegatedOwnerPending(delegated.decision, pid, uint32(os.Getpid()), ownerErr) {
			// A protected or LOCAL reserved socket cannot become self/DIRECT when ownership
			// lookup races its first SYN. Drop this packet; a retransmit can retry.
			t.b.evidence.RecordLocalInspection(delegated.owner.identity, delegated.owner.tuple, &localstrategy.Inspection{Reason: "DELEGATED_TCP_OWNER_NOT_CONFIRMED", Detail: "reserved SYN held until exact service owner is observable"})
			t.b.drop(delegated.owner.identity, tuple)
			return
		}
		owned = ownerErr == nil && pid == uint32(os.Getpid())
	}
	if owned {
		id = delegated.owner.identity
		decision = delegated.decision
		self = false
	}
	if flags&0x12 == 2 {
		outcome := ingressDecision(id, decision, true, self)
		if outcome == "NATIVE_DEFERRED_SYN" {
			t.b.ingress.nativeSYN.Add(1)
		}
		t.b.ingress.record("TCP_SYN_CLASSIFY", id, tuple, decision, outcome, ownerSource, ownerCode)
	}
	mode := "direct"
	if !self && (t.b.hotFrozen(decision) || flags&0x12 != 0x02 && needsHotAttach(decision)) {
		t.quarantineNative(id, tuple, decision, p, a)
		return
	}
	if flags&0x12 != 0x02 || self {
		decision.Local = nil
		decision.Route = routing.Route{}
		decision.Block = false
		decision.BlockOnFailure = false
		decision.Deferred = false
		decision.ResolveDomain = nil
		if !self {
			decision.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "existing_tcp", Reason: "pre-existing TCP connection is not reclassified"}
		}
	}
	if flags&0x12 == 0x02 && !self && id.PID != 0 {
		if decision.Block {
			mode = "block"
		} else if !decision.Route.Direct() || decision.Deferred || decision.OpenDeferred != nil {
			mode = "opening"
		}
	}
	t.state.mu.Lock()
	t.b.evidence.BeginFlow(id, tuple)
	t.b.evidence.RecordPolicy(id, tuple, decision, "")
	e = t.state.add(tuple, id, decision, mode, time.Now())
	if e == nil {
		t.state.mu.Unlock()
		if decision.Block || decision.BlockOnFailure {
			t.b.drop(id, tuple)
		} else {
			_ = t.send(p, a)
		}
		return
	}
	if owned {
		e.delegationOwner = delegated.owner
	}
	e.hotEpoch = t.b.policyEpoch.Load()
	t.b.evidence.RecordHotAttach(id, tuple, t.b.hot.snapshot().Epoch, "HOT_ATTACH_NEW_FLOW", decision.Revision)
	e.initialSequence = sequence
	t.record(e, "captured", len(p))
	if self {
		t.record(e, "self", len(p))
	}
	if mode == "opening" {
		if decision.Deferred {
			// No upstream work until accept/ClientHello. Do not consume an
			// opening permit for the app-side SYN handshake.
			e.mode = "relay"
			err = t.reflect(e, p, a, false)
		} else {
			e.openDone = make(chan struct{})
			syn := append([]byte(nil), p...)
			t.admitOpen(e, func(release func()) { t.open(e, syn, a, release) })
		}
	} else if mode == "direct" {
		err = e.localBuffer.Push(e.decision, &e.localState, e.identity, e.tuple, p, func(q []byte) error { return t.send(q, a) }, t.b.evidence, time.Now())
	} else {
		t.b.drop(id, tuple)
	}
	t.state.mu.Unlock()
	if err != nil && t.b.ctx.Err() == nil {
		t.b.fail(err)
	}
}

// Called with state.mu held. Capture and accept never wait for an opening
// permit. Only setup work queues; established pipe goroutines hold no permits.
func (t *tcpRedirect) admitOpen(e *tcpEntry, run func(func())) {
	t.wg.Add(1)
	ctx, cancel := context.WithCancel(t.b.ctx)
	e.openCancel = cancel
	t.b.evidence.RecordTCPAdmission(e.identity, e.tuple, "TCP_ADMISSION_QUEUED", 0)
	fail := func(cause string, wait time.Duration) {
		t.b.evidence.RecordTCPAdmission(e.identity, e.tuple, cause, wait)
		t.b.evidence.RecordFailure(e.identity, e.tuple, cause, true)
		t.state.retire(e, time.Now())
		e.finishOpen()
		t.wg.Done()
	}
	if !t.admission.submit(ctx, func(wait time.Duration, err error, release func()) {
		defer cancel()
		if err != nil {
			t.state.mu.Lock()
			if e.mode != "closed" && e.mode != "hot_attach" && t.b.ctx.Err() == nil {
				fail("TCP_ADMISSION_TIMEOUT", wait)
			} else {
				e.finishOpen()
				t.wg.Done()
			}
			t.state.mu.Unlock()
			return
		}
		t.b.evidence.RecordTCPAdmission(e.identity, e.tuple, "TCP_ADMISSION_READY", wait)
		run(release)
	}) {
		// A genuine hard resource bound (384 pending setups), not temporary
		// saturation of the 128 workers. Never bypass protected policy.
		cancel()
		fail("TCP_ADMISSION_LIMIT", 0)
	}
}

func (t *tcpRedirect) open(e *tcpEntry, syn []byte, a [80]byte, release func()) {
	defer t.wg.Done()
	defer e.finishOpen()
	defer release()
	t.state.mu.Lock()
	valid := t.state.entries[e.tuple] == e && e.mode == "opening"
	t.state.mu.Unlock()
	if !valid {
		return
	}
	ctx, cancel := context.WithTimeout(t.b.ctx, 5*time.Second)
	t.state.mu.Lock()
	e.openCancel = cancel
	retired := e.mode != "opening"
	t.state.mu.Unlock()
	if retired {
		cancel()
		return
	}
	openStarted := time.Now()
	decision := e.decision
	planned := decision.OpenDeferred != nil
	var up net.Conn
	var err error
	if planned {
		up, decision, err = decision.OpenDeferred(ctx, decision, "CONNECT_AUTHORITY")
	} else {
		up, err = t.b.Engine.OpenTCP(ctx, decision.Flow)
	}
	cancel()
	route := decision.Route
	if err == nil && !planned {
		for _, f := range t.b.Engine.Snapshot() {
			if f.Protocol == "tcp" && f.PID == e.identity.PID && f.Source == e.tuple.Source && f.Destination == e.tuple.Destination {
				route = f.Route
				break
			}
		}
	}
	t.state.mu.Lock()
	defer t.state.mu.Unlock()
	if t.b.ctx.Err() != nil || t.state.entries[e.tuple] != e || e.mode != "opening" {
		if up != nil {
			up.Close()
		}
		return
	}
	e.decision = decision
	if planned {
		t.b.evidence.RecordPolicy(e.identity, e.tuple, decision, "CONNECT_AUTHORITY")
	}
	if !route.Direct() {
		t.b.evidence.RecordRelayOpen(e.identity, e.tuple, openStarted, err)
	}
	if err != nil || route.Direct() && !planned {
		if up != nil {
			up.Close()
		}
		if e.decision.BlockOnFailure {
			t.b.evidence.RecordPolicy(e.identity, e.tuple, e.decision, "RELAY_OPEN_FAILED")
			e.mode = "block"
			t.b.drop(e.identity, e.tuple)
			return
		}
		e.mode = "direct"
		e.decision.Route = route
		err = t.send(syn, a)
		t.record(e, "direct", len(syn))
	} else {
		e.upstream = up
		e.mode = "relay"
		e.decision.Route = route
		err = t.reflect(e, syn, a, false)
	}
	if err != nil {
		t.b.fail(err)
	}
}
func (t *tcpRedirect) accept() {
	defer t.wg.Done()
	for {
		c, err := t.listener.AcceptTCP()
		if err != nil {
			return
		}
		local, remote := c.LocalAddr().(*net.TCPAddr).AddrPort(), c.RemoteAddr().(*net.TCPAddr).AddrPort()
		t.traceFixture("accept", Tuple{Protocol: "tcp", Source: remote, Destination: local}, 0, 0)
		t.state.mu.Lock()
		e := t.state.ports[remote.Port()]
		if t.b.ctx.Err() != nil || e == nil || e.mode != "relay" || e.local != nil || (e.upstream == nil && !e.decision.Deferred) || local.Addr() != e.tuple.Source.Addr() || remote.Addr() != e.tuple.Destination.Addr() {
			t.state.mu.Unlock()
			c.Close()
			continue
		}
		t.b.ingress.accepted.Add(1)
		t.b.ingress.record("TCP_REFLECTION_ACCEPT", e.identity, e.tuple, e.decision, "LOCAL_TCP_ACCEPTED", "EXACT_REFLECTION_MAPPING", "")
		e.local = c
		if e.decision.Deferred {
			e.openDone = make(chan struct{})
		}
		up := e.upstream
		if e.decision.Deferred {
			t.admitOpen(e, func(release func()) { t.deferredOpen(e, c, release) })
			t.state.mu.Unlock()
		} else {
			t.wg.Add(1)
			t.state.mu.Unlock()
			go t.pipe(e, c, up)
		}
	}
}
func (t *tcpRedirect) pipe(e *tcpEntry, local, up net.Conn) {
	defer t.wg.Done()
	// Half-close permits HTTP/1.0, uploads and protocols which wait for EOF.
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.copy(e, up, local, "relay")
		if h, ok := up.(interface{ CloseWrite() error }); ok {
			_ = h.CloseWrite()
		}
	}()
	t.copy(e, local, up, "reply")
	local.Close()
	up.Close()
	<-done
	t.state.mu.Lock()
	if e.mode != "closed" {
		e.mode = "closed"
		e.last = time.Now()
	}
	e.local = nil
	e.upstream = nil
	t.state.mu.Unlock()
}
func (t *tcpRedirect) copy(e *tcpEntry, dst, src net.Conn, event string) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := writeTCP(dst, buf[:n])
			if written > 0 {
				// Only the finite first-flight wrapper reports a changing
				// upstream decision. This updates evidence, never reroutes TCP.
				upstream := src
				if event == "relay" {
					upstream = dst
				}
				var policy flowpolicy.Result
				known := false
				if reporter, ok := upstream.(TCPPolicyReporter); ok {
					policy, known = reporter.CurrentTCPPolicy()
				}
				t.state.mu.Lock()
				if known && policy != e.decision.Policy {
					e.decision.Policy = policy
					switch policy.Action {
					case flowpolicy.Direct:
						e.decision.Route = routing.Route{}
					case flowpolicy.DirectPlus:
						e.decision.Route = routing.Route{Kind: routing.DirectPlusRoute}
					case flowpolicy.RelayRequired:
						e.decision.Route = routing.Route{RelayID: policy.RelayID}
					}
					t.b.evidence.RecordPolicy(e.identity, e.tuple, e.decision, "TLS_FIRST_FLIGHT_STAGE")
				}
				e.last = time.Now()
				actualEvent := event
				if e.decision.Route.Direct() {
					actualEvent = "direct_proxy"
				}
				t.b.evidence.AddBytes(e.identity, e.tuple, actualEvent, e.decision.Route.RelayID, uint64(written))
				t.state.mu.Unlock()
				if event == "relay" {
					t.b.TX.Add(uint64(written))
				} else {
					t.b.RX.Add(uint64(written))
				}
			}
			if werr != nil {
				t.finishCopy(e, event, nil, werr)
				return
			}
		}
		if err != nil {
			t.finishCopy(e, event, err, nil)
			return
		}
	}
}
func (t *tcpRedirect) finishCopy(e *tcpEntry, event string, readErr, writeErr error) {
	t.state.mu.Lock()
	defer t.state.mu.Unlock()
	stopping := t.b.ctx.Err() != nil || (e.mode == "closed" || e.mode == "hot_attach") || e.normalTeardown
	cause := tcpCopyFailure(event, readErr, writeErr, stopping)
	if cause != "" {
		t.b.evidence.RecordFailure(e.identity, e.tuple, cause, e.decision.BlockOnFailure)
	}
	if tcpNormalEnd(event, readErr, writeErr) {
		e.normalTeardown = true
		t.b.evidence.RecordLifecycle(e.identity, e.tuple, "TCP_CLOSED")
	}
}
func writeTCP(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (t *tcpRedirect) cleanup() {
	defer t.wg.Done()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-t.b.ctx.Done():
			return
		case now := <-tick.C:
			t.state.mu.Lock()
			for _, e := range t.state.entries {
				if e.localBuffer.Expired(now) {
					if err := e.localBuffer.Flush(e.decision, &e.localState, e.identity, e.tuple, now, "REASSEMBLY_TIMEOUT", t.b.evidence); err != nil {
						t.b.fail(err)
					}
				}
			}
			t.state.expire(now)
			t.pruneEvidenceAliases()
			t.state.mu.Unlock()
		}
	}
}

// The app-side handshake has completed locally; upstream is opened exactly once
// after outer SNI. A failure closes this connection, never retries its TLS bytes
// on a different egress. Only a future connection can choose a different route.
func (t *tcpRedirect) deferredOpen(e *tcpEntry, c net.Conn, release func()) {
	defer e.finishOpen()
	defer release()
	t.state.mu.Lock()
	valid := t.state.entries[e.tuple] == e && e.mode == "relay"
	t.state.mu.Unlock()
	if !valid {
		c.Close()
		t.wg.Done()
		return
	}
	data, domain, reason := ReadDeferredHello(c)
	if reason == "CLIENT_CLOSED_BEFORE_DATA" {
		t.state.mu.Lock()
		t.state.retire(e, time.Now())
		t.state.mu.Unlock()
		t.wg.Done()
		return
	}
	d := ResolveDeferredDecision(e.decision, domain, reason)
	if reason == "ECH_OUTER_SNI_ONLY" {
		domain = ""
	}
	t.state.mu.Lock()
	if t.b.ctx.Err() != nil || (e.mode == "closed" || e.mode == "hot_attach") {
		t.state.mu.Unlock()
		c.Close()
		t.wg.Done()
		return
	}
	e.decision = d
	t.b.evidence.RecordPolicy(e.identity, e.tuple, d, reason)
	t.b.evidence.RecordDomain(e.identity, e.tuple, domain)
	t.state.mu.Unlock()
	if d.Block {
		t.state.mu.Lock()
		t.b.drop(e.identity, e.tuple)
		t.state.retire(e, time.Now())
		t.state.mu.Unlock()
		t.wg.Done()
		return
	}
	requested := d.Route
	ctx, cancel := context.WithTimeout(t.b.ctx, 5*time.Second)
	t.state.mu.Lock()
	e.openCancel = cancel
	retired := e.mode == "hot_attach" || e.mode == "closed"
	t.state.mu.Unlock()
	if retired {
		cancel()
		c.Close()
		t.wg.Done()
		return
	}
	var up net.Conn
	var err error
	openStarted := time.Now()
	if d.OpenDeferred != nil {
		up, d, err = d.OpenDeferred(ctx, d, reason)
		requested = d.Route
	} else if d.Route.Local() {
		up, err = t.dialLocalStrategy(ctx, e, d)
	} else {
		up, err = t.b.Engine.OpenTCP(ctx, d.Flow)
	}
	cancel()
	if err != nil && !errors.Is(err, routing.ErrFleetPolicy) && d.OpenDeferred == nil && !d.BlockOnFailure && t.b.ctx.Err() == nil && (!requested.Direct() || requested.Local()) {
		// No application bytes have left this proxy yet. An explicitly permitted
		// native fallback gets its own bounded open budget, not an expired relay ctx.
		fallback, stop := context.WithTimeout(t.b.ctx, 3*time.Second)
		up, err = (&net.Dialer{}).DialContext(fallback, "tcp4", e.tuple.Destination.String())
		stop()
		if err == nil {
			d.Route = routing.Route{}
			reason = "UPSTREAM_OPEN_FAIL_OPEN_DIRECT"
		}
	}
	if err == nil && !d.Route.Local() {
		for _, f := range t.b.Engine.Snapshot() {
			if f.Protocol == "tcp" && f.PID == e.identity.PID && f.Source == e.tuple.Source && f.Destination == e.tuple.Destination {
				d.Route = f.Route
				break
			}
		}
	}
	t.state.mu.Lock()
	if t.state.entries[e.tuple] != e || e.mode == "hot_attach" || e.mode == "closed" {
		t.state.mu.Unlock()
		abortHotTCP(up)
		c.Close()
		t.wg.Done()
		return
	}
	e.decision = d
	if d.OpenDeferred != nil {
		t.b.evidence.RecordPolicy(e.identity, e.tuple, d, reason)
	}
	if !requested.Direct() {
		t.b.evidence.RecordRelayOpen(e.identity, e.tuple, openStarted, err)
	}
	if reason == "UPSTREAM_OPEN_FAIL_OPEN_DIRECT" {
		t.b.evidence.RecordPolicy(e.identity, e.tuple, d, reason)
	}
	if err != nil || t.b.ctx.Err() != nil || (e.mode == "closed" || e.mode == "hot_attach") {
		if up != nil {
			up.Close()
		}
		t.b.evidence.RecordPolicy(e.identity, e.tuple, d, "UPSTREAM_OPEN_FAILED")
		t.b.drop(e.identity, e.tuple)
		t.state.retire(e, time.Now())
		t.state.mu.Unlock()
		t.wg.Done()
		return
	}
	e.upstream = up
	if !requested.Direct() && d.Route.Direct() {
		t.b.evidence.RecordPolicy(e.identity, e.tuple, d, "RELAY_FELL_BACK_DIRECT")
	}
	t.b.evidence.RecordUpstreamOpened(e.identity, e.tuple, d.Route)
	t.state.mu.Unlock()
	// Established writes can block on peer backpressure indefinitely; they
	// must never retain an opening permit and starve unrelated new flows.
	release()
	e.finishOpen()
	if len(data) > 0 {
		n, werr := writeTCP(up, data)
		if n > 0 {
			event := "direct_proxy"
			if !d.Route.Direct() {
				event = "relay"
			}
			t.b.evidence.AddBytes(e.identity, e.tuple, event, d.Route.RelayID, uint64(n))
		}
		if werr != nil {
			t.finishCopy(e, "relay", nil, werr)
			c.Close()
			up.Close()
			t.state.mu.Lock()
			t.state.retire(e, time.Now())
			t.state.mu.Unlock()
			t.wg.Done()
			return
		}
	}
	data = nil
	t.pipe(e, c, up)
}
func (t *tcpRedirect) dialLocalStrategy(ctx context.Context, e *tcpEntry, d Decision) (net.Conn, error) {
	return t.dialLocalStrategyFrom(ctx, e, d, e.tuple.Source.Addr())
}
func (t *tcpRedirect) dialLocalStrategyFrom(ctx context.Context, e *tcpEntry, d Decision, bind netip.Addr) (net.Conn, error) {
	return t.dialDelegatedFrom(ctx, e, d, bind, false)
}
func (t *tcpRedirect) dialDelegatedFrom(ctx context.Context, e *tcpEntry, d Decision, bind netip.Addr, deferred bool) (net.Conn, error) {
	wireDestination := e.tuple.Destination
	if deferred {
		wireDestination = t.b.nativeDelegationDestination(wireDestination)
	}
	var bound Tuple
	c, err := dialBoundIPv4Options(ctx, bind, wireDestination, func(source netip.AddrPort) error {
		if bound.Source.IsValid() {
			t.releaseDelegated(bound, e.identity)
		}
		bound = Tuple{Protocol: "tcp", Source: source, Destination: wireDestination}
		t.delegatedMu.Lock()
		defer t.delegatedMu.Unlock()
		if len(t.delegated) >= t.state.limit || !t.b.evidence.BindUpstream(e.identity, bound, e.tuple) {
			return fmt.Errorf("delegated TCP limit")
		}
		d.Flow = routing.Flow{}
		if !deferred {
			d.Deferred = false
			d.ResolveDomain = nil
		}
		t.delegated[bound] = delegatedTCP{owner: e, decision: d}
		return nil
	}, !deferred && browserTimestampPlan(d))
	if err != nil {
		if deferred {
			t.abortUnacceptedDelegated(bound, e.identity)
		}
		t.releaseDelegated(bound, e.identity)
		return nil, err
	}
	release := func() { t.releaseDelegated(bound, e.identity) }
	if deferred {
		release = func() {
			t.state.closePlannedDelegation(bound, e)
			t.delegatedMu.Lock()
			if current, ok := t.delegated[bound]; ok && current.owner == e {
				delete(t.delegated, bound)
				t.b.evidence.UnbindUpstream(e.identity, bound)
			}
			t.delegatedMu.Unlock()
		}
	}
	return &delegatedConn{Conn: c, release: release}, nil
}

// A failed frontend handoff has transmitted no application bytes. Close only
// its exact unaccepted reservation before releasing the alias, so a retry does
// not collide with an orphaned authenticated upstream or affect an active pipe.
func (t *tcpRedirect) abortUnacceptedDelegated(bound Tuple, id ProcessIdentity) {
	t.state.mu.Lock()
	defer t.state.mu.Unlock()
	e := t.state.entries[bound]
	if e == nil || !sameHotOwner(e.identity, id) || e.decision.OpenDeferred == nil || e.local != nil || (e.mode != "opening" && e.mode != "relay") {
		return
	}
	if e.openCancel != nil {
		e.openCancel()
	}
	t.b.evidence.RecordFailure(e.identity, e.tuple, "NATIVE_CLIENT_HANDOFF_FAILED", true)
	t.state.retire(e, time.Now())
}

// Closing a delegated upstream can happen while state.mu is held. Its release
// must not re-enter that mutex or leave aliases pointing at a new policy epoch.
func (t *tcpRedirect) releaseDelegated(bound Tuple, id ProcessIdentity) {
	t.delegatedMu.Lock()
	delete(t.delegated, bound)
	t.delegatedMu.Unlock()
	t.b.evidence.UnbindUpstream(id, bound)
}

func (c *delegatedConn) Abort() error {
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	return c.Close()
}

type delegatedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *delegatedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *delegatedConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

// Caller holds state.mu. Keep the pre-SYN reservation as well as captured state:
// cleanup can run between BindUpstream and the first captured SYN. Lock order is
// state -> delegated -> evidence, matching dialLocalStrategyFrom; no inverse
// callback lock is acquired from inside EvidenceLedger.pruneAliases.
func (t *tcpRedirect) pruneEvidenceAliases() {
	t.delegatedMu.Lock()
	defer t.delegatedMu.Unlock()
	t.b.evidence.pruneAliases(func(tuple Tuple) bool {
		_, reserved := t.delegated[tuple]
		return reserved || t.state.entries[tuple] != nil
	})
}

func (t *tcpRedirect) traceFixture(phase string, tuple Tuple, flags, addr byte) {
	if !t.b.testBrowserLoopback {
		return
	}
	hook := t.fixtureTrace.Load()
	if hook == nil {
		return
	}
	test := netip.MustParseAddr("192.0.2.254")
	if tuple.Source.Addr() != test && tuple.Destination.Addr() != test && tuple.Source.Port() != t.port && tuple.Destination.Port() != t.port {
		return
	}
	hook.f(phase, tuple, flags, addr)
}
