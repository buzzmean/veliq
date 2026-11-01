package windowsplatform

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

// QUICProbeSocket owns one connected service UDP socket. The OS sends ordinary
// UDP datagrams; no raw injection, interception or capture delegation is needed.
// The browser identity scopes permission to probe, not ownership of this socket.
type QUICProbeSocket struct {
	conn   net.Conn
	scope  QUICProbeScope
	writer *QUICProbeWriter
	once   sync.Once
	closed atomic.Bool
	stopMu sync.Mutex
	stop   func() bool
}

func OpenQUICProbeSocket(ctx context.Context, scope QUICProbeScope, repeats uint8, current func(QUICProbeScope) bool) (*QUICProbeSocket, error) {
	return openQUICProbeSocket(ctx, scope, repeats, current, IsCurrent, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", dst.String())
	})
}

func openQUICProbeSocket(ctx context.Context, scope QUICProbeScope, repeats uint8, current func(QUICProbeScope) bool, ownerCurrent func(ProcessIdentity) bool, dial func(context.Context, netip.AddrPort) (net.Conn, error)) (*QUICProbeSocket, error) {
	if ctx.Err() != nil || scope.Source.IsValid() || current == nil || !ownerCurrent(scope.Owner) || !current(scope) {
		return nil, errors.New("QUIC_PROBE_SCOPE_INVALID")
	}
	// Validate all immutable fields before allocating a socket. The OS chooses
	// the real source; never reuse a browser tuple or accept a supplied source.
	validation := scope
	validation.Source = netip.MustParseAddrPort("127.0.0.1:1")
	if _, err := NewQUICProbeWriter(validation, repeats, current); err != nil {
		return nil, err
	}
	conn, err := dial(ctx, scope.Destination)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			conn.Close()
		}
	}()
	source, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil || conn.RemoteAddr().String() != scope.Destination.String() {
		return nil, errors.New("QUIC_PROBE_SOCKET_TUPLE_INVALID")
	}
	scope.Source = source
	guard := func(s QUICProbeScope) bool { return ctx.Err() == nil && ownerCurrent(s.Owner) && current(s) }
	if !guard(scope) {
		return nil, errors.New("QUIC_PROBE_SCOPE_CHANGED")
	}
	writer, err := NewQUICProbeWriter(scope, repeats, guard)
	if err != nil {
		return nil, err
	}
	s := &QUICProbeSocket{conn: conn, scope: scope, writer: writer}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	s.stopMu.Lock()
	if s.closed.Load() {
		stop()
	} else {
		s.stop = stop
	}
	s.stopMu.Unlock()
	failed = false
	return s, nil
}

func (s *QUICProbeSocket) Committed() bool { return !s.closed.Load() && s.writer.Evidence().Committed }

// The HTTP/3 layer verifies Host with TLS on this endpoint. All other scope
// fields must match this exact owned socket before it sends its first datagram.
func (s *QUICProbeSocket) ScopeMatches(k browserproxy.HTTP3ProbeKey) bool {
	return !s.closed.Load() && s.scope.Owner.PID == k.PID && s.scope.Owner.CreationTime == k.Birth && s.scope.Owner.Path == k.Executable && s.scope.Destination == k.Endpoint && s.scope.Network == k.Network && s.scope.Profile == k.Profile && s.scope.Revision == k.Revision
}
func (s *QUICProbeSocket) Evidence() QUICProbeSendEvidence    { return s.writer.Evidence() }
func (s *QUICProbeSocket) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *QUICProbeSocket) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *QUICProbeSocket) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *QUICProbeSocket) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
func (s *QUICProbeSocket) Close() error {
	var err error
	s.once.Do(func() { s.closed.Store(true); err = s.conn.Close() })
	s.stopMu.Lock()
	stop := s.stop
	s.stop = nil
	s.stopMu.Unlock()
	if stop != nil {
		stop()
	}
	return err
}
func (s *QUICProbeSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := s.conn.Read(p)
	return n, net.UDPAddrFromAddrPort(s.scope.Destination), err
}
func (s *QUICProbeSocket) WriteTo(payload []byte, addr net.Addr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if addr == nil || addr.String() != s.scope.Destination.String() || len(payload) > 1472 {
		s.Close()
		return 0, errors.New("QUIC_PROBE_SOCKET_TUPLE_INVALID")
	}
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	src, dst := s.scope.Source.Addr().As4(), s.scope.Destination.Addr().As4()
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], s.scope.Source.Port())
	binary.BigEndian.PutUint16(p[22:24], s.scope.Destination.Port())
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	err := s.writer.Send(p, func(out []byte) error {
		tuple, data, err := ParseUDP(out)
		if err != nil || tuple.Source != s.scope.Source || tuple.Destination != s.scope.Destination {
			return errors.New("QUIC_PROBE_SOCKET_TUPLE_INVALID")
		}
		n, err := s.conn.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}
