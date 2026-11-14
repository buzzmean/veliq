// Package transport multiplexes flow handles over a persistent secure QUIC connection.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/telemetry"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var ErrClosed = errors.New("flow or session closed")
var ErrRelayRejected = errors.New("relay rejected flow")

type sessionEnd struct{ reason string }

type Client struct {
	handshakeMS    float64
	endReason      atomic.Pointer[sessionEnd]
	controlReplies chan []byte
	controlSend    chan struct{}
	leaseChanged   chan struct{}
	conn           *quic.Conn
	localAddr      net.Addr
	relayAddr      net.Addr
	pathMu         sync.Mutex
	pathTransports []*quic.Transport // Non-nil only for a migration-capable session.
	leaseMu        sync.Mutex
	renewalOnce    sync.Once
	lease          LeaseSnapshot
	next           atomic.Uint32
	packetSequence atomic.Uint32
	reassembly     protocol.Reassembly
	mu             sync.Mutex
	flows          map[uint32]*UDPFlow
	done           chan struct{}
	drops          atomic.Uint64
	LocalDrops     telemetry.Counters
	onFailure      func(string)
}
type UDPFlow struct {
	client *Client
	id     uint32
	stream *quic.Stream
	queue  chan []byte
	done   chan struct{}
	once   sync.Once
}

func Dial(ctx context.Context, addr string, t *tls.Config) (*Client, error) {
	start := time.Now()
	c, e := quic.DialAddr(ctx, addr, t, ClientQUICConfig())
	if e != nil {
		return nil, e
	}
	if !c.ConnectionState().SupportsDatagrams {
		c.CloseWithError(1, "datagrams required")
		return nil, errors.New("relay lacks QUIC DATAGRAM")
	}
	x := newClient(c, float64(time.Since(start))/float64(time.Millisecond))
	go x.receive()
	return x, nil
}

func newClient(conn *quic.Conn, handshakeMS float64) *Client {
	return &Client{handshakeMS: handshakeMS, conn: conn, localAddr: conn.LocalAddr(), relayAddr: conn.RemoteAddr(), flows: make(map[uint32]*UDPFlow), done: make(chan struct{})}
}

func (c *Client) Close() error          { return c.conn.CloseWithError(0, "shutdown") }
func (c *Client) Done() <-chan struct{} { return c.done }
func (c *Client) Dropped() uint64       { return c.drops.Load() }

// SetFailureHandler observes real relay I/O failures without retrying game packets.
func (c *Client) SetFailureHandler(handler func(string)) {
	c.mu.Lock()
	c.onFailure = handler
	c.mu.Unlock()
}
func (c *Client) reportFailure(reason string) {
	if end := c.SessionEndReason(); end == "authorization_lease_expired" || end == "device_revoked" {
		return
	}
	c.mu.Lock()
	handler := c.onFailure
	c.mu.Unlock()
	if handler != nil {
		handler(reason)
	}
}
func (c *Client) open(ctx context.Context, kind byte, dst netip.AddrPort) (*quic.Stream, uint32, error) {
	id := c.next.Add(1)
	if id == 0 {
		c.Close()
		return nil, 0, errors.New("flow IDs exhausted")
	}
	s, e := c.conn.OpenStream()
	if e != nil {
		e = streamCapacity(e)
		return nil, 0, &OpenError{Reason: openIOReason(e, c.SessionEndReason()), Cause: e}
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	s.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { s.CancelRead(1); s.CancelWrite(1) })
	defer stop()
	phase := "request_write"
	if e = (protocol.Open{Kind: kind, ID: id, Destination: dst}).Write(s); e == nil {
		phase = "ack_read"
		var ack [1]byte
		_, e = io.ReadFull(s, ack[:])
		if e == nil && ack[0] != 0 {
			cause := error(ErrRelayRejected)
			if ack[0] == 3 {
				cause = errors.Join(ErrCapacity, ErrRelayRejected)
			}
			e = &OpenError{Reason: protocol.OpenRejection(ack[0]), Cause: cause}
		}
	}
	if e != nil {
		// The caller's cancellation hook resets the stream. Preserve its budget
		// cause so a local deadline race is not mislabeled as a peer stream reset.
		if ctx.Err() != nil && !errors.Is(e, ErrRelayRejected) {
			e = errors.Join(ctx.Err(), e)
		}
		s.CancelRead(1)
		s.CancelWrite(1)
		reason := openIOReason(e, c.SessionEndReason())
		if phase == "request_write" && reason == "open_ack_timeout" {
			reason = "open_request_write_timeout"
		}
		return nil, 0, &OpenError{Reason: reason, Cause: fmt.Errorf("OPEN %s: %w", phase, e)}
	}
	s.SetDeadline(time.Time{})
	return s, id, nil
}
func (c *Client) OpenUDP(ctx context.Context, dst netip.AddrPort) (*UDPFlow, error) {
	s, id, e := c.open(ctx, protocol.UDP, dst)
	if e != nil {
		if c.conn.Context().Err() != nil && !errors.Is(ctx.Err(), context.Canceled) && !telemetry.IsLocal(e) {
			if reason := c.SessionEndReason(); reason != "authorization_lease_expired" && reason != "device_revoked" {
				c.reportFailure(FailureReason(e))
			}
		}
		return nil, e
	}
	f := &UDPFlow{client: c, id: id, stream: s, queue: make(chan []byte, 32), done: make(chan struct{})}
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		s.CancelRead(1)
		s.CancelWrite(1)
		return nil, ErrClosed
	default:
	}
	c.flows[id] = f
	c.mu.Unlock()
	go func() { var b [1]byte; _, _ = s.Read(b[:]); f.Close() }()
	return f, nil
}
func (c *Client) OpenTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	s, _, e := c.open(ctx, protocol.TCP, dst)
	if e != nil {
		return nil, e
	}
	return &streamConn{Stream: s, local: c.localAddr, remote: c.relayAddr}, nil
}
func (c *Client) receive() {
	defer func() {
		if reason := c.SessionEndReason(); reason != "" {
			c.leaseMu.Lock()
			c.lease.State = reason
			c.leaseMu.Unlock()
		}
		close(c.done)
		c.mu.Lock()
		all := make([]*UDPFlow, 0, len(c.flows))
		for _, f := range c.flows {
			all = append(all, f)
		}
		c.mu.Unlock()
		for _, f := range all {
			f.Close()
		}
		c.closePathTransports()
	}()
	for {
		b, e := c.conn.ReceiveDatagram(context.Background())
		if e != nil {
			if reason := AuthorizationEndReason(e); reason != "" {
				c.rememberEndReason(reason)
			} else {
				c.rememberEndReason("session_transport_closed")
			}
			return
		}
		if c.controlReplies != nil && len(b) > 0 && b[0] == protocol.LeaseAckDatagram {
			if _, err := protocol.ParseLeaseAckFrame(b); err == nil {
				select {
				case c.controlReplies <- b:
				default:
				}
			}
			continue
		}
		c.LocalDrops.Attempt(telemetry.Decode)
		c.LocalDrops.Attempt(telemetry.UnknownFlow)
		id, p, e := c.reassembly.Decode(b, time.Now())
		if e != nil {
			c.drops.Add(1)
			c.LocalDrops.Drop(telemetry.Decode)
			continue
		}
		if p == nil {
			continue
		}
		c.mu.Lock()
		f := c.flows[id]
		c.mu.Unlock()
		if f == nil {
			c.drops.Add(1)
			c.LocalDrops.Drop(telemetry.UnknownFlow)
			continue
		}
		if !c.LocalDrops.TryEnqueue(f.queue, p, telemetry.TransportQueue) {
			c.drops.Add(1)
		}
	}
}
func (f *UDPFlow) Send(p []byte) error {
	select {
	case <-f.done:
		return ErrClosed
	case <-f.client.done:
		return ErrClosed
	default:
	}
	parts, e := protocol.EncodeDatagrams(f.id, f.client.packetSequence.Add(1), p)
	if e != nil {
		return &telemetry.LocalError{Category: telemetry.CaptureProcessing, Cause: e}
	}
	f.client.LocalDrops.Attempt(telemetry.SocketSend)
	var err error
	for _, b := range parts {
		if err = f.client.conn.SendDatagram(b); err != nil {
			break
		}
	}
	if err != nil {
		f.client.LocalDrops.Drop(telemetry.SocketSend)
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			return &telemetry.LocalError{Category: telemetry.SocketSend, Cause: err}
		}
		f.client.reportFailure("transport_send_failed")
	}
	return err
}
func (f *UDPFlow) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-f.done:
		return nil, ErrClosed
	case <-f.client.done:
		return nil, ErrClosed
	default:
	}
	select {
	case b := <-f.queue:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		return nil, ErrClosed
	case <-f.client.done:
		return nil, ErrClosed
	}
}
func (f *UDPFlow) Close() error {
	f.once.Do(func() {
		close(f.done)
		f.client.mu.Lock()
		delete(f.client.flows, f.id)
		f.client.mu.Unlock()
		f.stream.CancelRead(0)
		f.stream.Close()
	})
	return nil
}

type streamConn struct {
	*quic.Stream
	local, remote net.Addr
}

// The tunneled stream retains its logical endpoints across a QUIC path change.
func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }
func (s *streamConn) Close() error         { s.CancelRead(0); return s.Stream.Close() }
func (s *streamConn) CloseWrite() error    { return s.Stream.Close() }

// FlowID/StreamID identify the established mapping; renewal never changes them.
func (f *UDPFlow) FlowID() uint32     { return f.id }
func (f *UDPFlow) StreamID() int64    { return int64(f.stream.StreamID()) }
func (c *streamConn) StreamID() int64 { return int64(c.Stream.StreamID()) }
