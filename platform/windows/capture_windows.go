//go:build windows

package windowsplatform

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/telemetry"
	"golang.org/x/sys/windows"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type queuedDatagram struct {
	payload  []byte
	enqueued time.Time
}
type captureFlow struct {
	game         *gameudp.Flow
	quicNotified bool
	quicOrigin   quicOriginCaptureState
	recovering   atomic.Bool
	policyEpoch  uint64
	cancelOpen   context.CancelFunc
	retired      bool
	opening      bool
	localState   localstrategy.State
	decision     Decision
	dropCause    telemetry.Category
	queue        chan queuedDatagram
	done         chan struct{}
	once         sync.Once
	datagram     routing.Datagram
	template     []byte
	address      [80]byte
	identity     ProcessIdentity
	endpoint     uint64
	lastSeen     time.Time
}
type WinDivertBackend struct {
	dnsSlots chan struct{}

	gameGuard                gameGuardState
	gameReflect, gameReplies uintptr
	gameEval                 *windows.Proc
	ingress                  captureIngress
	quicOrigins              quicOriginPool
	testBrowserLoopback      bool // Set only from export_test.go, never production configuration.
	policyEpoch              atomic.Uint64
	policyMu                 sync.RWMutex
	transition               map[string]bool
	transitionAll            bool
	hot                      hotAttachState
	hotRequests              chan struct{}
	classify                 Classifier
	Files                    DriverFiles
	Engine                   *routing.Engine
	RX, TX, Drops            atomic.Uint64
	LocalDrops               telemetry.Counters
	mu                       sync.Mutex
	life                     sync.Mutex
	status                   CaptureStatus
	dll                      *divertDLL
	native                   *divertDLL
	network, flow            uintptr
	socket                   uintptr
	ipv6                     uintptr
	v6guard                  IPv6Guard
	flows                    map[Tuple]*captureFlow
	associations             *FlowAssociations
	ctx                      context.Context
	cancel                   context.CancelFunc
	wg                       sync.WaitGroup
	packetWriter             func([]byte, [80]byte) error // optional native test seam; production uses WinDivert
	openWorkers              chan struct{}                // setup only; never held for UDP flow lifetime
	admission                udpAdmission
	cache                    *ProcessCache
	tcp                      *tcpRedirect
	evidence                 *EvidenceLedger
}

func NewWinDivert(files DriverFiles, engine *routing.Engine) *WinDivertBackend {
	return &WinDivertBackend{dnsSlots: make(chan struct{}, 16), Files: files, Engine: engine, status: CaptureStatus{Backend: "WinDivert", Capabilities: Capabilities{UDP: true, TCP: true, IPv4: true, Transparent: true}}, flows: make(map[Tuple]*captureFlow), associations: NewAssociations(8192), hotRequests: make(chan struct{}, 1), openWorkers: make(chan struct{}, 64), cache: NewProcessCache(NewDiscovery(), IsCurrent), evidence: NewEvidenceLedger()}
}
func (b *WinDivertBackend) Status() CaptureStatus { b.mu.Lock(); defer b.mu.Unlock(); return b.status }
func (d *divertDLL) openHandle(filter string, layer uintptr, flags uintptr) (uintptr, error) {
	return d.openHandlePriority(filter, layer, flags, 0)
}
func (d *divertDLL) openHandlePriority(filter string, layer uintptr, flags uintptr, priority int16) (uintptr, error) {
	if err := compileDivertFilter(d.compile, filter, layer); err != nil {
		return 0, err
	}
	s, e := windows.BytePtrFromString(filter)
	if e != nil {
		return 0, e
	}
	h, _, callErr := d.open.Call(uintptr(unsafe.Pointer(s)), layer, uintptr(priority), flags)
	if h == ^uintptr(0) {
		return 0, fmt.Errorf("WinDivertOpen(layer=%d filter=%q flags=%d): %w; administrator access and signed driver required", layer, filter, flags, callErr)
	}
	return h, nil
}
func (b *WinDivertBackend) Start(parent context.Context, classify Classifier) (result error) {
	defer func() {
		if result != nil {
			b.mu.Lock()
			b.status.Ready = false
			b.status.Error = result.Error()
			b.mu.Unlock()
		}
	}()
	b.life.Lock()
	defer b.life.Unlock()
	b.mu.Lock()
	if b.dll != nil {
		b.mu.Unlock()
		return errors.New("capture already started")
	}
	b.mu.Unlock()
	dll, e := loadDivert(b.Files)
	if e != nil {
		b.mu.Lock()
		b.status.Error = e.Error()
		b.mu.Unlock()
		return e
	}
	flow, e := dll.openHandle(captureFlowFilter, 2, 1|4)
	if e != nil {
		dll.dll.Release()
		return e
	}
	network, e := dll.openHandle(captureUDPFilter, 0, 0)
	if e != nil {
		dll.close.Call(flow)
		dll.dll.Release()
		return e
	}
	socket, e := dll.openHandle(captureSocketFilter, 3, 1|4)
	if e != nil {
		dll.close.Call(network)
		dll.close.Call(flow)
		dll.dll.Release()
		return e
	}
	ipv6, e := dll.openHandle(captureIPv6Filter, 0, 0)
	if e != nil {
		dll.close.Call(socket)
		dll.close.Call(network)
		dll.close.Call(flow)
		dll.dll.Release()
		return e
	}
	var major uint64
	ok, _, _ := dll.getParam.Call(network, 3, uintptr(unsafe.Pointer(&major)))
	if ok == 0 || major != 2 {
		dll.close.Call(ipv6)
		dll.close.Call(socket)
		dll.close.Call(network)
		dll.close.Call(flow)
		dll.dll.Release()
		return errors.New("WinDivert v2 driver required")
	}
	dll.setParam.Call(network, 0, 256)
	dll.setParam.Call(network, 1, 100)
	dll.setParam.Call(network, 2, 512*1024)
	tcp, e := b.startTCP(dll)
	if e != nil {
		dll.close.Call(ipv6)
		dll.close.Call(socket)
		dll.close.Call(network)
		dll.close.Call(flow)
		dll.dll.Release()
		return e
	}
	// Optional game-only observation. Failure suspends priming, never the
	// ordinary networking/capture backend. Open REFLECT before the final sniff
	// handle: its own priority marker fences the replayed initial handle list.
	b.gameGuard.reset()
	reflectHandle, reflectErr := dll.openHandle(captureReflectFilter, 4, 1|4)
	var replyHandle uintptr
	eval, evalErr := dll.dll.FindProc("WinDivertHelperEvalFilter")
	if reflectErr == nil && evalErr == nil {
		replyHandle, reflectErr = dll.openHandlePriority(gameUDPReplyFilter, 0, 1|4, gameReplyPriority)
	}
	if reflectErr != nil || evalErr != nil {
		b.gameGuard.fail("UDP_CONFLICT_DETECTOR_UNAVAILABLE")
		if reflectHandle != 0 {
			dll.close.Call(reflectHandle)
		}
		reflectHandle = 0
		if replyHandle != 0 {
			dll.close.Call(replyHandle)
		}
		replyHandle = 0
	}
	b.mu.Lock()
	b.gameReflect, b.gameReplies, b.gameEval = reflectHandle, replyHandle, eval
	b.tcp = tcp
	b.socket = socket
	b.ipv6 = ipv6
	b.v6guard = IPv6Guard{}
	b.dll = dll
	b.native = dll
	b.flow = flow
	b.network = network
	b.ctx, b.cancel = context.WithCancel(parent)
	b.classify = classify
	b.status.Ready = true
	b.status.Error = ""
	b.mu.Unlock()
	// TCP handle is already diverting, and no TCP consumer has started yet.
	// Established rows are pre-activation; queued new SYN_SENT rows are excluded.
	b.snapshotHotTargets()
	b.wg.Add(6)
	go b.hotAttachWorker()
	go b.track()
	go b.socketGuard(classify)
	go b.guardIPv6(classify)
	go b.cleanup()
	if b.gameReflect != 0 {
		b.wg.Add(1)
		go b.observeGameReflect()
	}
	if b.gameReplies != 0 {
		b.wg.Add(1)
		go b.observeGameReplies()
	}
	go b.packets(classify)
	tcp.start(classify)
	watch := b.ctx
	go func() {
		<-watch.Done()
		b.life.Lock()
		defer b.life.Unlock()
		if b.ctx == watch {
			b.stopLocked()
		}
	}()
	return nil
}
func (b *WinDivertBackend) Stop() error { b.life.Lock(); defer b.life.Unlock(); return b.stopLocked() }
func (b *WinDivertBackend) stopLocked() error {
	b.mu.Lock()
	if b.dll == nil {
		b.mu.Unlock()
		return nil
	}
	d := b.dll
	b.cancel()
	b.status.Ready = false
	b.dll = nil
	d.shutdown.Call(b.network, 1)
	d.shutdown.Call(b.flow, 1)
	d.shutdown.Call(b.socket, 1)
	d.shutdown.Call(b.ipv6, 1)
	if b.gameReflect != 0 {
		d.shutdown.Call(b.gameReflect, 1)
	}
	if b.gameReplies != 0 {
		d.shutdown.Call(b.gameReplies, 1)
	}
	for _, f := range b.flows {
		f.once.Do(func() { close(f.done) })
	}
	b.mu.Unlock()
	b.tcp.stop()
	b.wg.Wait()
	d.close.Call(b.network)
	d.close.Call(b.flow)
	d.close.Call(b.socket)
	d.close.Call(b.ipv6)
	if b.gameReflect != 0 {
		d.close.Call(b.gameReflect)
	}
	if b.gameReplies != 0 {
		d.close.Call(b.gameReplies)
	}
	d.dll.Release()
	b.mu.Lock()
	b.flows = make(map[Tuple]*captureFlow)
	b.quicOrigins.clear()
	b.associations = NewAssociations(8192)
	b.mu.Unlock()
	return nil
}
func (b *WinDivertBackend) track() {
	defer b.wg.Done()
	d := b.proc()
	discovery := b.cache
	var address [80]byte
	for {
		ok, _, e := d.recv.Call(b.flow, 0, 0, 0, uintptr(unsafe.Pointer(&address[0])))
		if ok == 0 {
			if b.ctx.Err() == nil {
				b.fail(fmt.Errorf("WinDivert flow receive: %w", e))
			}
			return
		}
		if b.ctx.Err() != nil {
			return
		}
		if address[10]&0x10 != 0 {
			continue
		}
		data := address[16:]
		pid := binary.LittleEndian.Uint32(data[16:20])
		proto := "udp"
		if data[56] == 6 {
			proto = "tcp"
		} else if data[56] != 17 {
			continue
		}
		src, dst := [4]byte{}, [4]byte{}
		binary.BigEndian.PutUint32(src[:], binary.LittleEndian.Uint32(data[32:36]))
		binary.BigEndian.PutUint32(dst[:], binary.LittleEndian.Uint32(data[48:52]))
		tuple := Tuple{proto, netip.AddrPortFrom(netip.AddrFrom4(src), binary.LittleEndian.Uint16(data[52:54])), netip.AddrPortFrom(netip.AddrFrom4(dst), binary.LittleEndian.Uint16(data[54:56]))}
		endpoint := binary.LittleEndian.Uint64(data[:8])
		event := address[9]
		if event == 2 {
			b.associations.Delete(tuple, endpoint)
			b.mu.Lock()
			if f := b.flows[tuple]; f != nil && f.endpoint == endpoint {
				f.once.Do(func() { close(f.done) })
				delete(b.flows, tuple)
			}
			b.mu.Unlock()
			continue
		}
		identity, e := discovery.Lookup(pid)
		if e == nil {
			b.associations.Put(Association{identity, tuple, endpoint})
			// FLOW can arrive after the first packet/owner fallback. Consume proof for
			// an already-observed tuple instead of rearming it after packet-cache expiry.
			b.mu.Lock()
			if b.flows[tuple] != nil {
				b.associations.MarkGameFirstFlight(tuple, identity)
			}
			b.mu.Unlock()
		}
	}
}

// proc is retained until receive loops have stopped; Stop only clears publication.
func (b *WinDivertBackend) proc() *divertDLL { return b.native }
func (b *WinDivertBackend) fail(e error) {
	b.mu.Lock()
	b.status.Error = e.Error()
	b.mu.Unlock()
	b.cancel()
}
func (b *WinDivertBackend) inject(d *divertDLL, p []byte, a [80]byte) error {
	if b.packetWriter != nil {
		return b.packetWriter(p, a)
	}
	d.checksum.Call(uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(&a[0])), 0)
	var sent uint32
	ok, _, e := d.send.Call(b.network, uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(&a[0])))
	if ok == 0 {
		return fmt.Errorf("packet reinjection: %w", e)
	}
	b.evidence.Record(ProcessIdentity{}, Tuple{}, "reinject", "")
	return nil
}
func (b *WinDivertBackend) packets(classify Classifier) {
	defer b.wg.Done()
	d := b.proc()
	buffer := make([]byte, 65535)
	for {
		var n uint32
		var address [80]byte
		ok, _, e := d.recv.Call(b.network, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&address[0])))
		if ok == 0 {
			if b.ctx.Err() == nil {
				b.LocalDrops.Drop(telemetry.CaptureReceiveErrors)
				b.fail(fmt.Errorf("WinDivert packet receive: %w", e))
			}
			return
		}
		if n == 0 || n > uint32(len(buffer)) {
			b.LocalDrops.Drop(telemetry.CaptureProcessing)
			b.fail(errors.New("invalid WinDivert packet size"))
			return
		}
		b.processUDP(d, buffer[:n], address, classify)
	}
}
func (b *WinDivertBackend) processUDP(d *divertDLL, packet []byte, address [80]byte, classify Classifier) {
	b.policyMu.RLock()
	defer b.policyMu.RUnlock()

	tuple, payload, e := ParseUDP(packet)
	if e != nil || b.ctx.Err() != nil {
		if e = b.inject(d, packet, address); e != nil && b.ctx.Err() == nil {
			b.fail(e)
			return
		}
		return
	}
	b.associations.mu.RLock()
	association, known := b.associations.items[tuple]
	b.associations.mu.RUnlock()
	identity := association.Identity
	known = known && IsCurrent(identity)
	if !known {
		identity = ProcessIdentity{}
		if pid, err := resolveUDPOwner(tuple.Source); err == nil {
			if resolved, err := b.cache.Lookup(pid); err == nil {
				identity = resolved
				known = true
				association = Association{Identity: identity, Tuple: tuple}
				b.associations.Put(association)
			}
		}
	}
	b.associations.Touch(tuple)
	if known && tuple.Destination.Port() == 53 {
		decision, _ := ClassifyCapture(identity, tuple, uint32(os.Getpid()), classify)
		if decision.DNSExchange != nil {
			b.handleBrowserDNS(d, identity, tuple, packet, payload, address, decision)
			return
		}
	}
	if tuple.Destination.Port() == 443 {
		b.ingress.udp443.Add(1)
	}
	b.mu.Lock()
	f := b.flows[tuple]
	if f != nil && known {
		b.associations.MarkGameFirstFlight(tuple, identity)
	}
	if f != nil && f.retired {
		b.mu.Unlock()
		b.Drops.Add(1)
		b.evidence.RecordDrop(identity, tuple, "HOT_ATTACH_PENDING", false)
		return
	}
	if f != nil && known && f.identity.CreationTime == 0 {
		f.identity = identity
		f.policyEpoch = ^uint64(0)
		f.endpoint = association.Endpoint
		if f.game != nil {
			b.associations.MarkGameFirstFlight(tuple, identity)
		}
	}
	if f != nil && known && f.endpoint == 0 && f.identity.CreationTime == identity.CreationTime {
		f.endpoint = association.Endpoint
	}
	if f != nil && known && f.identity.CreationTime != 0 && (f.identity.PID != identity.PID || f.identity.CreationTime != identity.CreationTime) {
		f.once.Do(func() { close(f.done) })
		delete(b.flows, tuple)
		f = nil
	}
	if f != nil && f.policyEpoch != b.policyEpoch.Load() {
		latest, _ := ClassifyCapture(identity, tuple, uint32(os.Getpid()), classify)
		f.policyEpoch = b.policyEpoch.Load()
		if latest.GameUDP != nil && f.game == nil && latest.Revision != f.decision.Revision {
			// Already observed UDP never acquires a new first-flight strategy merely
			// because a late owner/profile appeared. Wait for a genuinely new tuple.
			latest.GameUDP = nil
			latest.Policy.Action = flowpolicy.Direct
			latest.Policy.Reason = "EXISTING_UDP_PINNED_UNTIL_CLOSED"
			f.decision = latest
		}
		if latest.Revision != f.decision.Revision {
			f.retired = true
			f.once.Do(func() { close(f.done) })
			if f.cancelOpen != nil {
				f.cancelOpen()
			}
			b.evidence.RecordHotAttach(identity, tuple, b.hot.snapshot().Epoch, "HOT_ATTACH_RETIRED", f.decision.Revision)
			if f.queue == nil {
				delete(b.flows, tuple)
				f = nil
			} else {
				b.mu.Unlock()
				b.Drops.Add(1)
				b.evidence.RecordDrop(identity, tuple, "HOT_ATTACH_PENDING", false)
				return
			}
		}
	}
	if f == nil {
		b.evidence.BeginFlow(identity, tuple)
	}
	b.evidence.RecordBytes(identity, tuple, "captured", "", uint64(len(packet)))
	if known && identity.PID == uint32(os.Getpid()) {
		b.evidence.Record(identity, tuple, "self", "")
	}
	if f == nil {
		decision := Decision{Route: routing.Route{}}
		if known {
			decision, _ = ClassifyCapture(identity, tuple, uint32(os.Getpid()), classify)
		}
		if tuple.Destination.Port() == 443 {
			b.ingress.record("UDP443_NETWORK", identity, tuple, decision, "UDP443_"+string(decision.Policy.Action), "UDP_OWNER_OR_FLOW", "")
		}
		if b.hotFrozen(decision) {
			b.evidence.RecordPolicy(identity, tuple, decision, "")
			b.evidence.RecordHotAttach(identity, tuple, b.hot.snapshot().Epoch, "HOT_ATTACH_PREEXISTING", decision.Revision)
			b.mu.Unlock()
			b.Drops.Add(1)
			b.evidence.RecordDrop(identity, tuple, "HOT_ATTACH_PENDING", false)
			return
		}
		b.evidence.RecordPolicy(identity, tuple, decision, "")
		if len(b.flows) >= 8192 {
			b.mu.Unlock()
			if decision.Block || decision.BlockOnFailure || decision.ProbeDirect {
				b.evidence.RecordFailure(identity, tuple, "UDP_FLOW_TABLE_CAPACITY", true)
				b.drop(identity, tuple)
			} else {
				if err := b.inject(d, packet, address); err != nil {
					b.fail(err)
					return
				}
				b.evidence.RecordBytes(identity, tuple, "direct", "", uint64(len(packet)))
			}
			return
		}

		if decision.GameUDP == nil {
			b.associations.MarkGameFirstFlight(tuple, identity)
		}
		var game *gameudp.Flow
		var gameErr error
		decision, game, gameErr = BindGameUDP(decision, identity, tuple, time.Now())
		if game != nil && !b.associations.MarkGameFirstFlight(tuple, identity) {
			decision.GameUDP.PinUnverifiedDirect(game)
			decision.Route = routing.Route{}
			decision.BlockOnFailure = false
			decision.Flow.PinnedPolicy = &routing.Policy{}
			decision.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "game_udp_ladder", Reason: "EXISTING_UDP_PINNED_DIRECT_NO_FIRST_FLIGHT_PROOF"}
		}
		if gameErr != nil {
			b.evidence.RecordLifecycle(identity, tuple, gameErr.Error())
		}
		f = &captureFlow{policyEpoch: b.policyEpoch.Load(), decision: decision, game: game, dropCause: telemetry.Policy, identity: identity, endpoint: association.Endpoint, done: make(chan struct{}), address: address}
		if (!decision.Route.Direct() || decision.ProbeDirect) && !decision.Block {
			f.opening = true
			f.queue = make(chan queuedDatagram, 32)
			f.template = udpReplyTemplate(packet)
		}

		b.flows[tuple] = f
		b.evidence.RecordPolicy(identity, tuple, decision, "")
		b.evidence.RecordHotAttach(identity, tuple, b.hot.snapshot().Epoch, "HOT_ATTACH_NEW_FLOW", decision.Revision)
		if f.game != nil && decision.GameUDP != nil {
			b.evidence.RecordGameUDP(identity, tuple, decision.GameUDP.Evidence(f.game))
		}
		if (!decision.Route.Direct() || decision.ProbeDirect) && !decision.Block {
			if b.admission.acquire(decision.ProbeDirect) {
				b.wg.Add(1)
				go b.forward(tuple, f, d)
			} else {
				f.opening = false
				f.queue = nil
				f.template = nil
				b.evidence.RecordFailure(identity, tuple, "UDP_WORKER_CAPACITY", true)
				if f.decision.BlockOnFailure || f.decision.ProbeDirect {
					f.dropCause = telemetry.WorkerSaturation
					f.decision.Block = true
				} else {
					f.decision.Route = routing.Route{}
				}
			}
		}
	}
	f.lastSeen = time.Now()
	decision := f.decision
	b.mu.Unlock()
	// An expired identity must not retain a previous process's BLOCK decision.
	if decision.Block && known && decision.Policy.Source == "browser_native_quic_tcp_fallback" {
		b.mu.Lock()
		notify := !f.quicNotified
		f.quicNotified = true
		// Passive metadata only: never change this flow's BLOCK decision,
		// forward/hold originals or use a sample as browser LOCAL authority.
		observed, publish := b.quicOrigins.observe(&f.quicOrigin, identity, tuple, decision, payload, notify, time.Now())
		b.mu.Unlock()
		if publish && IsCurrent(identity) {
			b.ingress.recordQUICOrigin(identity, tuple, decision, observed)
		}
		b.evidence.RecordQuicFallback(identity, tuple, "native-tcp", "browser")
		if notify {
			if reply, err := RejectBrowserQUIC(packet); err == nil {
				a := address
				a[10] &= ^byte(2)
				if err = b.inject(d, reply, a); err != nil && b.ctx.Err() == nil {
					b.fail(err)
					return
				}
			}
		}
	}
	if decision.Block && known {
		b.LocalDrops.Attempt(f.dropCause)
		b.LocalDrops.Drop(f.dropCause)
		b.drop(identity, tuple)
		return
	}
	if f.game != nil && decision.GameUDP != nil && known && decision.Route.Direct() {
		if !b.primeGameAllowed(packet, address) {
			decision.GameUDP.SetReason("FOREIGN_UDP_INTERCEPTOR_OR_OBSERVER_PENDING")
		}
		if err := SendGameUDP(decision.GameUDP, f.game, identity, tuple, packet, func(q []byte) error { return b.inject(d, q, address) }, b.evidence, time.Now()); err != nil {
			b.fail(err)
		}
		return
	}
	if (decision.Route.Direct() && !decision.ProbeDirect) || !known {
		if e = SendLocal(decision, &f.localState, identity, tuple, packet, func(q []byte) error { return b.inject(d, q, LocalPacketAddress(q, address)) }, b.evidence); e != nil {
			b.fail(e)
			return
		}
		return
	}
	if len(payload) > protocol.MaxPayload {
		b.LocalDrops.Attempt(telemetry.CaptureProcessing)
		b.LocalDrops.Drop(telemetry.CaptureProcessing)
		b.drop(identity, tuple)
		return
	}
	// Commit queueing under the same lock as fallback, so draining cannot miss a late enqueue.
	b.mu.Lock()
	latest := f.decision
	if latest.Block {
		b.mu.Unlock()
		b.LocalDrops.Attempt(telemetry.Policy)
		b.LocalDrops.Drop(telemetry.Policy)
		b.drop(identity, tuple)
		return
	}
	if latest.Route.Direct() && !latest.ProbeDirect {
		b.mu.Unlock()
		b.LocalDrops.Attempt(telemetry.CaptureProcessing)
		if err := b.inject(d, packet, address); err != nil {
			b.LocalDrops.Drop(telemetry.CaptureProcessing)
			b.fail(err)
			return
		}
		b.evidence.RecordBytes(identity, tuple, "direct", "", uint64(len(packet)))
		return
	}
	b.LocalDrops.Attempt(telemetry.CaptureQueue)
	select {
	case f.queue <- queuedDatagram{append([]byte(nil), payload...), time.Now()}:
		b.evidence.RecordUDPQueue(identity, tuple, len(f.queue), f.opening, false, 0)
	default:
		b.LocalDrops.Drop(telemetry.CaptureQueue)
		b.evidence.RecordUDPQueue(identity, tuple, cap(f.queue), f.opening, true, 0)
		b.Drops.Add(1)
		b.evidence.RecordDrop(identity, tuple, "UDP_QUEUE_CAPACITY", false)
	}
	b.mu.Unlock()
}

func (b *WinDivertBackend) forward(tuple Tuple, f *captureFlow, d *divertDLL) {
	defer b.wg.Done()
	defer func() {
		b.mu.Lock()
		if f.retired && b.flows[tuple] == f {
			delete(b.flows, tuple)
		}
		f.queue = nil
		f.template = nil
		b.admission.release(f.decision.ProbeDirect)
		b.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(b.ctx, 750*time.Millisecond)
	defer cancel()
	var datagram routing.Datagram
	var err error
	adaptive := f.decision.ProbeDirect
	openStarted := time.Now()
	// Limit simultaneous setup work, not the number of live sockets. Admission
	// is already reserved; waiting shares the existing 750ms setup budget.
	b.mu.Lock()
	f.cancelOpen = cancel
	b.mu.Unlock()
	select {
	case <-f.done:
		cancel()
		return
	default:
	}
	select {
	case b.openWorkers <- struct{}{}:
		if adaptive {
			datagram, err = b.Engine.OpenAdaptiveUDP(ctx, f.decision.Flow, f.decision.Policy.RelayID, 3*time.Second)
		} else {
			datagram, err = b.Engine.OpenUDP(ctx, f.decision.Flow)
		}
		<-b.openWorkers
	case <-ctx.Done():
		err = ctx.Err()
		b.evidence.RecordFailure(f.identity, tuple, "UDP_OPEN_CAPACITY", f.decision.BlockOnFailure || adaptive)
	}
	cancel()
	b.mu.Lock()
	retired := f.retired
	f.datagram = datagram
	f.opening = false
	b.mu.Unlock()
	if retired {
		if datagram != nil {
			datagram.Close()
		}
		return
	}
	if !adaptive {
		b.evidence.RecordRelayOpen(f.identity, tuple, openStarted, err)
		if err != nil && f.game != nil && f.decision.GameUDP != nil {
			f.decision.GameUDP.TransportFailed(f.game, "GAME_RELAY_OPEN_FAILED")
			b.evidence.RecordGameUDP(f.identity, tuple, f.decision.GameUDP.Evidence(f.game))
		}
	}
	if err == nil {
		for _, flow := range b.Engine.Snapshot() {
			if flow.PID == f.decision.Flow.PID && flow.Source == tuple.Source && flow.Destination == tuple.Destination {
				if flow.Route.Direct() && !adaptive {
					err = errors.New("relay setup fell back to DIRECT")
				} else {
					b.mu.Lock()
					f.decision.Route = flow.Route
					b.mu.Unlock()
				}
			}
		}
	}
	select {
	case <-f.done:
		if datagram != nil {
			datagram.Close()
		}
		return
	default:
	}
	if err != nil {
		if datagram != nil {
			datagram.Close()
		}
		b.fallback(tuple, f, d, nil)
		return
	}

	defer datagram.Close()
	var healthMu sync.Mutex // serialize snapshots from send/receive publishers
	publishHealth := func() {
		healthMu.Lock()
		defer healthMu.Unlock()
		if a, ok := datagram.(*routing.AdaptiveUDP); ok {
			// Adaptive transition can open relay while holding its mutex. Never
			// wait for it under the shared capture-map lock.
			health, route := a.Health(), a.Route()
			b.mu.Lock()
			if b.flows[tuple] == f {
				b.evidence.RecordUDPHealth(f.identity, tuple, health)
				f.decision.Route = route
			}
			b.mu.Unlock()
		}
	}
	publishHealth()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			recvCtx, cancel := context.WithTimeout(b.ctx, time.Second)
			payload, e := datagram.Receive(recvCtx)
			cancel()
			publishHealth()
			if e != nil {
				if b.ctx.Err() != nil {
					return
				}
				select {
				case <-f.done:
					return
				default:
				}
				if errors.Is(e, routing.ErrUDPRecovering) {
					f.recovering.Store(true)
					b.evidence.RecordLifecycle(f.identity, tuple, "UDP_RELAY_RECOVERING")
					continue
				}
				if errors.Is(e, context.DeadlineExceeded) {
					continue
				}
				return
			}
			b.mu.Lock()
			if b.flows[tuple] != f {
				b.mu.Unlock()
				return
			}
			f.lastSeen = time.Now()
			b.mu.Unlock()
			packet, e := ReplyUDP(f.template, payload)
			if e != nil {
				b.LocalDrops.Attempt(telemetry.ReplyReinjection)
				b.LocalDrops.Drop(telemetry.ReplyReinjection)
				b.drop(f.identity, tuple)
				continue
			}
			address := f.address
			address[10] &= ^byte(2)
			b.LocalDrops.Attempt(telemetry.ReplyReinjection)
			if err := b.inject(d, packet, address); err != nil {
				b.LocalDrops.Drop(telemetry.ReplyReinjection)
				b.fail(err)
				return
			}
			if f.recovering.Swap(false) {
				b.evidence.RecordLifecycle(f.identity, tuple, "UDP_RELAY_RECOVERED")
			}
			var adaptiveRoute routing.Route
			if a, ok := datagram.(*routing.AdaptiveUDP); ok {
				adaptiveRoute = a.Route()
			}
			b.mu.Lock()
			if f.retired || b.flows[tuple] != f {
				b.mu.Unlock()
				return
			}
			route := f.decision.Route.RelayID
			if adaptive {
				route = adaptiveRoute.RelayID
				f.decision.Route = adaptiveRoute
			}
			if b.flows[tuple] != f {
				b.mu.Unlock()
				return
			}
			event := "reply"
			if route == "" {
				event = "direct_reply"
			}
			b.evidence.RecordBytes(f.identity, tuple, event, route, uint64(len(payload)))
			if f.game != nil && f.decision.GameUDP != nil {
				f.decision.GameUDP.Reply(f.game, len(payload), time.Now())
				b.evidence.RecordGameUDP(f.identity, tuple, f.decision.GameUDP.Evidence(f.game))
			}
			b.mu.Unlock()
			b.RX.Add(uint64(len(payload)))
		}
	}()
	defer func() { datagram.Close(); <-done }()
	idleTick := time.NewTicker(time.Second)
	defer idleTick.Stop()
	retireIdle := func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.flows[tuple] != f || !udpIdle(time.Now(), f.lastSeen, len(f.queue), udpIdleLimit(tuple, adaptive)) {
			return false
		}
		// Close tracked Engine state before exposing a vacant capture tuple.
		// No pending application payload is replayed or discarded here.
		datagram.Close()
		f.once.Do(func() { close(f.done) })
		delete(b.flows, tuple)
		b.evidence.RecordLifecycle(f.identity, tuple, "UDP_IDLE_EXPIRED")
		return true
	}
	for {
		select {
		case <-b.ctx.Done():
			datagram.Close()
			<-done
			return
		case <-f.done:
			datagram.Close()
			<-done
			return
		case <-idleTick.C:
			if retireIdle() {
				datagram.Close()
				<-done
				return
			}
		case <-done:
			if retireIdle() {
				return
			}
			b.fallback(tuple, f, d, nil)
			return
		case queued := <-f.queue:
			payload := queued.payload
			select {
			case <-f.done:
				datagram.Close()
				<-done
				return
			default:
			}
			b.evidence.RecordUDPQueue(f.identity, tuple, 0, false, false, time.Since(queued.enqueued))
			sendErr := datagram.Send(payload)
			publishHealth()
			if errors.Is(sendErr, routing.ErrUDPRecovering) {
				f.recovering.Store(true)
				b.evidence.RecordLifecycle(f.identity, tuple, "UDP_RELAY_RECOVERING")
				b.evidence.RecordDrop(f.identity, tuple, "UDP_RELAY_RECOVERING", false)
				b.Drops.Add(1)
				continue
			}
			if sendErr != nil {
				b.fallback(tuple, f, d, payload)
				datagram.Close()
				<-done
				return
			}
			var adaptiveRoute routing.Route
			if a, ok := datagram.(*routing.AdaptiveUDP); ok {
				adaptiveRoute = a.Route()
			}
			b.mu.Lock()
			if f.retired || b.flows[tuple] != f {
				b.mu.Unlock()
				return
			}
			route := f.decision.Route.RelayID
			if adaptive {
				route = adaptiveRoute.RelayID
				f.decision.Route = adaptiveRoute
			}
			policy := f.decision
			b.mu.Unlock()
			event := "relay"
			if route == "" {
				event = "direct"
			} else if adaptive {
				why := datagram.(*routing.AdaptiveUDP).Reason()
				if why == "LEARNED_RECENT_DIRECT_FAILURE" {
					policy.Policy.Source = "endpoint_cache"
				}
				b.evidence.RecordPolicy(f.identity, tuple, policy, why)
			}
			b.evidence.RecordBytes(f.identity, tuple, event, route, uint64(len(payload)))
			if f.game != nil && f.decision.GameUDP != nil {
				f.decision.GameUDP.Outgoing(f.game, len(payload), time.Now())
				b.evidence.RecordGameUDP(f.identity, tuple, f.decision.GameUDP.Evidence(f.game))
			}
			b.TX.Add(uint64(len(payload)))
		}
	}
}

func (b *WinDivertBackend) Traffic() (uint64, uint64) { return b.RX.Load(), b.TX.Load() }

func (b *WinDivertBackend) Diagnostics(pid uint32) CaptureEvidence {
	return b.DiagnosticsTarget(pid, "")
}
func (b *WinDivertBackend) CaptureChangeMarker() ChangeCursor { return b.evidence.ChangeMarker() }
func (b *WinDivertBackend) CaptureChanges(q ChangeQuery) (ChangePage, error) {
	return b.evidence.ChangePage(q)
}
func (b *WinDivertBackend) CaptureMarker() EvidenceMarker { return b.evidence.Marker() }
func (b *WinDivertBackend) DiagnosticsTarget(pid uint32, destination string) CaptureEvidence {
	out, _ := b.DiagnosticsScoped(EvidenceQuery{PID: pid, Destination: destination})
	return out
}
func (b *WinDivertBackend) DiagnosticsScoped(query EvidenceQuery) (CaptureEvidence, error) {
	b.mu.Lock()
	tcp := b.tcp
	b.mu.Unlock()
	active := map[evidenceKey]bool{}
	if tcp != nil {
		tcp.state.mu.Lock()
		for _, e := range tcp.state.entries {
			if e.mode == "relay" && e.local != nil && e.upstream != nil {
				active[evidenceKey{e.identity.PID, e.identity.CreationTime, e.tuple}] = true
			}
		}
		tcp.state.mu.Unlock()
	}
	out, err := b.evidence.SnapshotQuery(query, active)
	if err != nil {
		return out, err
	}
	for i := range out.Flows {
		f := &out.Flows[i]
		f.IdentityCurrent = IsCurrent(ProcessIdentity{PID: f.PID, CreationTime: f.CreationTime, Path: f.Executable})
	}
	ingress := b.ingress.snapshot(query.PID)
	out.Ingress = &ingress
	for len(ingress.Records) > 0 {
		raw, _ := json.Marshal(out)
		if len(raw) <= 60*1024 {
			break
		}
		ingress.Records = ingress.Records[1:]
		ingress.Lost++
	}
	out.Counters.Dropped = b.Drops.Load()
	out.LocalDrops = b.LocalDrops.Snapshot()
	out.LocalDrops["capture_kernel_queue_drops"] = telemetry.Metric{Available: false, Unit: "packets"}
	return out, nil
}
func (b *WinDivertBackend) fallback(tuple Tuple, f *captureFlow, d *divertDLL, failed []byte) {
	b.mu.Lock()
	if f.retired || b.flows[tuple] != f {
		b.mu.Unlock()
		return
	}
	block := f.decision.BlockOnFailure || f.decision.ProbeDirect
	f.decision.Block = block
	if !block {
		f.decision.Route = routing.Route{}
	}
	b.mu.Unlock()
	if f.game != nil && f.decision.GameUDP != nil {
		f.decision.GameUDP.TransportFailed(f.game, "GAME_RELAY_TRANSPORT_FAILED")
		b.evidence.RecordGameUDP(f.identity, tuple, f.decision.GameUDP.Evidence(f.game))
	}
	b.evidence.RecordPolicy(f.identity, tuple, b.flowDecision(f), "TRANSPORT_FAILED")
	b.evidence.RecordFailure(f.identity, tuple, "TRANSPORT_FAILED", block)
	inject := func(payload []byte) {
		if block {
			b.drop(f.identity, tuple)
			return
		}
		p, err := ReplyUDP(f.template, payload)
		if err != nil {
			b.drop(f.identity, tuple)
			return
		}
		ihl := int(p[0]&15) * 4
		copy(p[12:20], f.template[12:20])
		copy(p[ihl:ihl+4], f.template[ihl:ihl+4])
		if err = b.inject(d, p, f.address); err != nil {
			b.fail(err)
			return
		}
		b.evidence.RecordBytes(f.identity, tuple, "direct", "", uint64(len(p)))
	}
	if failed != nil {
		inject(failed)
	}
	for {
		select {
		case queued := <-f.queue:
			b.evidence.RecordUDPQueue(f.identity, tuple, 0, false, false, time.Since(queued.enqueued))
			inject(queued.payload)
		default:
			return
		}
	}
}
func (b *WinDivertBackend) cleanup() {
	defer b.wg.Done()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case now := <-tick.C:
			b.cache.Cleanup(now)
			b.evidence.Cleanup(now)
			b.associations.Cleanup(now)
			b.v6guard.Cleanup(now)
			b.mu.Lock()
			for t, f := range b.flows {
				if f.queue == nil && now.Sub(f.lastSeen) > 60*time.Second {
					f.once.Do(func() { close(f.done) })
					delete(b.flows, t)
				}
			}
			b.mu.Unlock()
		}
	}
}

func (b *WinDivertBackend) drop(id ProcessIdentity, t Tuple) {
	b.Drops.Add(1)
	b.evidence.RecordDrop(id, t, "POLICY_BLOCK", true)
}

func (b *WinDivertBackend) flowDecision(f *captureFlow) Decision {
	b.mu.Lock()
	defer b.mu.Unlock()
	return f.decision
}

func (b *WinDivertBackend) CaptureIngressStatus() CaptureIngressSnapshot {
	return b.ingress.snapshot(0)
}
