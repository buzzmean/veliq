package routing

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/protocol"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrFlowExists = errors.New("flow already pinned")
var ErrLimit = errors.New("flow limit reached")

type Datagram interface {
	Send([]byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}
type Relay interface {
	OpenDatagram(context.Context, netip.AddrPort) (Datagram, error)
	OpenTCP(context.Context, netip.AddrPort) (net.Conn, error)
}
type Policy struct {
	Route          Route
	BlockOnFailure bool
	Auto           bool
	Block          bool
	Backups        []Route
	ExactRelay     bool // This route was measured against a specific physical relay.
	RelayAddress   string
}
type Key struct {
	Protocol            string
	Source, Destination netip.AddrPort
	PID                 uint32
}
type Engine struct {
	healthMu     sync.Mutex
	health       map[udpHealthKey]udpHealth
	mu           sync.Mutex
	policies     map[string]Policy
	relays       map[string]Relay
	exactRelays  map[string]exactRelay
	flows        map[Key]Flow
	limit        int
	selectPolicy func(Flow) Policy
	onBytes      func(Flow, uint64, uint64)
}

type exactRelay struct {
	address string
	relay   Relay
}

func New(limit int) *Engine {
	if limit <= 0 {
		limit = 4096
	}
	return &Engine{health: map[udpHealthKey]udpHealth{}, policies: make(map[string]Policy), relays: make(map[string]Relay), exactRelays: make(map[string]exactRelay), flows: make(map[Key]Flow), limit: limit}
}
func (e *Engine) SetAutoSelector(pick func(Flow) Policy) {
	e.mu.Lock()
	e.selectPolicy = pick
	e.mu.Unlock()
}
func (e *Engine) SetPolicy(app string, p Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[app] = p
}
func (e *Engine) SetRelay(id string, r Relay) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r == nil {
		delete(e.relays, id)
	} else {
		e.relays[id] = r
	}
}
func (e *Engine) SetExactRelay(id, address string, r Relay) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r == nil {
		delete(e.exactRelays, id)
		return
	}
	e.exactRelays[id] = exactRelay{address, r}
}
func key(f Flow) Key { return Key{f.Protocol, f.Source, f.Destination, f.PID} }
func (e *Engine) reserve(f Flow) (Key, Policy, Relay, error) {
	if !f.Destination.IsValid() || f.Destination.Port() == 0 || !f.Source.IsValid() || f.Source.Port() == 0 {
		return Key{}, Policy{}, nil, errors.New("invalid flow tuple")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	k := key(f)
	if _, ok := e.flows[k]; ok {
		return k, Policy{}, nil, ErrFlowExists
	}
	if len(e.flows) >= e.limit {
		return k, Policy{}, nil, ErrLimit
	}
	p := e.policies[f.ApplicationID]
	// Unidentified processes always bypass optimization, including matching app labels.
	if f.PID == 0 || f.ProcessPath == "" || f.ApplicationID == "" {
		p = Policy{}
	}
	if f.PinnedPolicy != nil && f.PID != 0 && f.ProcessPath != "" && f.ApplicationID != "" {
		p = *f.PinnedPolicy
		p.Backups = append([]Route(nil), p.Backups...)
	} else if p.Auto && e.selectPolicy != nil {
		selected := e.selectPolicy(f)
		selected.BlockOnFailure = p.BlockOnFailure
		p = selected
	}
	if p.Block {
		return k, p, nil, errors.New("application blocked by policy")
	}
	f.Route = p.Route
	f.CreatedAt = time.Now()
	f.LastActivity = f.CreatedAt
	e.flows[k] = f
	if p.ExactRelay {
		node := e.exactRelays[p.Route.RelayID]
		if p.RelayAddress == "" || p.RelayAddress != node.address {
			return k, p, nil, nil
		}
		return k, p, node.relay, nil
	}
	return k, p, e.relays[p.Route.RelayID], nil
}
func (e *Engine) remove(k Key) { e.mu.Lock(); delete(e.flows, k); e.mu.Unlock() }

// Observer runs AFTER releasing the engine lock; accounting cannot reenter or
// stall routing while holding its critical section. It never chooses a route.
func (e *Engine) SetTrafficObserver(fn func(Flow, uint64, uint64)) {
	e.mu.Lock()
	e.onBytes = fn
	e.mu.Unlock()
}
func (e *Engine) account(k Key, tx, rx uint64) {
	e.mu.Lock()
	f, ok := e.flows[k]
	callback := e.onBytes
	if ok {
		f.LastActivity = time.Now()
		e.flows[k] = f
	}
	e.mu.Unlock()
	if ok && callback != nil && f.Route.RelayID != "" {
		callback(f, tx, rx)
	}
}

func (e *Engine) pinRoute(k Key, r Route) {
	e.mu.Lock()
	f := e.flows[k]
	f.Route = r
	e.flows[k] = f
	e.mu.Unlock()
}
func (e *Engine) direct(k Key) {
	e.mu.Lock()
	f := e.flows[k]
	f.Route = Route{}
	e.flows[k] = f
	e.mu.Unlock()
}
func (e *Engine) Snapshot() []Flow {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Flow, 0, len(e.flows))
	for _, f := range e.flows {
		out = append(out, f)
	}
	return out
}
func (e *Engine) OpenUDP(ctx context.Context, f Flow) (Datagram, error) {
	f.Protocol = "udp"
	k, p, r, err := e.reserve(f)
	if err != nil {
		return nil, err
	}
	var d Datagram
	if !p.Route.Direct() {
		routes := []Route{p.Route}
		if !p.ExactRelay {
			routes = append(routes, p.Backups...)
		}
		for i, route := range routes {
			if i >= 3 || route.Direct() {
				break
			}
			provider := r
			if i > 0 {
				e.mu.Lock()
				provider = e.relays[route.RelayID]
				e.mu.Unlock()
			}
			if provider == nil {
				err = errors.New("relay unavailable")
				continue
			}
			attempt, stop := context.WithTimeout(ctx, 3*time.Second)
			d, err = provider.OpenDatagram(attempt, f.Destination)
			stop()
			if err == nil && d != nil {
				e.pinRoute(k, route)
				break
			}
			d = nil
		}
		if d == nil && p.BlockOnFailure {
			e.remove(k)
			return nil, err
		}
	}
	if d == nil {
		e.direct(k)
		c, er := (&net.Dialer{}).DialContext(ctx, "udp", f.Destination.String())
		err = er
		if err == nil {
			d = &directUDP{c: c}
		}
	}
	if err != nil {
		e.remove(k)
		return nil, err
	}
	if p.BlockOnFailure && !p.Route.Direct() && !p.ExactRelay {
		// Reopen only this protected UDP mapping, retaining its pinned relay decision.
		// No policy reevaluation, DIRECT fallback, endpoint-cache learning or payload replay.
		e.mu.Lock()
		route := e.flows[k].Route
		provider := e.relays[route.RelayID]
		e.mu.Unlock()
		d = &recoveringUDP{current: d, open: func(ctx context.Context) (Datagram, error) {
			e.mu.Lock()
			provider = e.relays[route.RelayID]
			e.mu.Unlock()
			if provider == nil {
				return nil, errors.New("required relay unavailable")
			}
			return provider.OpenDatagram(ctx, f.Destination)
		}}
	}
	return &trackedUDP{Datagram: d, e: e, k: k}, nil
}
func (e *Engine) OpenTCP(ctx context.Context, f Flow) (net.Conn, error) {
	f.Protocol = "tcp"
	k, p, r, err := e.reserve(f)
	if err != nil {
		return nil, err
	}
	var c net.Conn
	if !p.Route.Direct() {
		routes := append([]Route{p.Route}, p.Backups...)
		for i, route := range routes {
			if i >= 3 || route.Direct() {
				break
			}
			provider := r
			if i > 0 {
				e.mu.Lock()
				provider = e.relays[route.RelayID]
				e.mu.Unlock()
			}
			if provider == nil {
				err = errors.New("relay unavailable")
				continue
			}
			attempt, stop := context.WithTimeout(ctx, 3*time.Second)
			c, err = provider.OpenTCP(attempt, f.Destination)
			stop()
			if err == nil && c != nil {
				e.pinRoute(k, route)
				break
			}
			c = nil
		}
		if c == nil && p.BlockOnFailure {
			e.remove(k)
			return nil, err
		}
	}
	if c == nil {
		e.direct(k)
		c, err = (&net.Dialer{}).DialContext(ctx, "tcp", f.Destination.String())
	}
	if err != nil {
		e.remove(k)
		return nil, err
	}
	return &trackedTCP{Conn: c, e: e, k: k}, nil
}

type trackedUDP struct {
	Datagram
	e    *Engine
	k    Key
	once sync.Once
}

func (f *trackedUDP) Send(b []byte) error {
	err := f.Datagram.Send(b)
	if err == nil {
		f.e.account(f.k, uint64(len(b)), 0)
	}
	return err
}
func (f *trackedUDP) Receive(ctx context.Context) ([]byte, error) {
	b, err := f.Datagram.Receive(ctx)
	if err == nil {
		f.e.account(f.k, 0, uint64(len(b)))
	}
	return b, err
}
func (f *trackedUDP) Close() error {
	err := f.Datagram.Close()
	f.once.Do(func() { f.e.remove(f.k) })
	return err
}

type directUDP struct {
	c      net.Conn
	readMu sync.Mutex
}

func (f *directUDP) Send(b []byte) error {
	if len(b) > protocol.MaxPayload {
		return protocol.ErrFrame
	}
	_, err := f.c.Write(b)
	return err
}
func (f *directUDP) Receive(ctx context.Context) ([]byte, error) {
	f.readMu.Lock()
	defer f.readMu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	d := time.Time{}
	if t, ok := ctx.Deadline(); ok {
		d = t
	}
	f.c.SetReadDeadline(d)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { f.c.SetReadDeadline(time.Now()); close(finished) })
	defer func() {
		if !stop() {
			<-finished
		}
		f.c.SetReadDeadline(time.Time{})
	}()
	b := make([]byte, protocol.MaxPayload+1)
	n, err := f.c.Read(b)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if n > protocol.MaxPayload {
		return nil, protocol.ErrFrame
	}
	return b[:n], err
}
func (f *directUDP) Close() error { return f.c.Close() }

type trackedTCP struct {
	net.Conn
	e    *Engine
	k    Key
	once sync.Once
}

func (f *trackedTCP) Read(b []byte) (int, error) {
	n, err := f.Conn.Read(b)
	if n > 0 {
		f.e.account(f.k, 0, uint64(n))
	}
	return n, err
}
func (f *trackedTCP) Write(b []byte) (int, error) {
	n, err := f.Conn.Write(b)
	if n > 0 {
		f.e.account(f.k, uint64(n), 0)
	}
	return n, err
}
func (f *trackedTCP) Close() error {
	err := f.Conn.Close()
	f.once.Do(func() { f.e.remove(f.k) })
	return err
}
func (f *trackedTCP) CloseWrite() error {
	if h, ok := f.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return errors.New("half-close unsupported")
}

// Abort is used only for an explicit per-application policy activation. It drops
// native pending sends rather than flushing an obsolete DIRECT egress on close.
func (f *trackedTCP) Abort() error {
	if a, ok := f.Conn.(interface{ SetLinger(int) error }); ok {
		_ = a.SetLinger(0)
	}
	if a, ok := f.Conn.(interface{ Abort() error }); ok {
		_ = a.Abort()
	}
	return f.Close()
}
