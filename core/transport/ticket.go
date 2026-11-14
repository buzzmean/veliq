package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"time"
)

func DialWithTicket(ctx context.Context, addr string, t *tls.Config, ticket []byte) (*Client, error) {
	c, err := dialWithTicket(ctx, addr, t, ticket, nil)
	if err == nil {
		go c.receive()
	}
	return c, err
}

// DialWithTicketPathMigration opts an authenticated session into same-peer
// local path validation. Non-zero QUIC connection IDs must be negotiated on
// the initial handshake so the peer's path responses can reach a second socket.
func DialWithTicketPathMigration(ctx context.Context, addr string, t *tls.Config, ticket []byte) (*Client, error) {
	peer, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: socket}
	c, err := dialWithTicket(ctx, addr, t, ticket, func(ctx context.Context, cfg *tls.Config) (*quic.Conn, error) {
		if cfg.ServerName == "" {
			cfg.ServerName, _, _ = net.SplitHostPort(addr)
		}
		return tr.Dial(ctx, peer, cfg, ClientQUICConfig())
	})
	if err != nil {
		_ = tr.Close()
		_ = socket.Close()
		return nil, err
	}
	c.pathTransports = []*quic.Transport{tr}
	go c.receive()
	return c, nil
}

func dialWithTicket(ctx context.Context, addr string, t *tls.Config, ticket []byte, pathDial func(context.Context, *tls.Config) (*quic.Conn, error)) (*Client, error) {
	cfg := t.Clone()
	cfg.NextProtos = []string{protocol.LeaseALPN, protocol.TicketALPN}
	start := time.Now()
	var conn *quic.Conn
	var e error
	if pathDial == nil {
		conn, e = quic.DialAddr(ctx, addr, cfg, ClientQUICConfig())
	} else {
		conn, e = pathDial(ctx, cfg)
	}
	if e != nil {
		return nil, e
	}
	handshakeMS := float64(time.Since(start)) / float64(time.Millisecond)
	fail := func(e error) (*Client, error) { conn.CloseWithError(1, "authentication failed"); return nil, e }
	if !conn.ConnectionState().SupportsDatagrams {
		return fail(errors.New("relay lacks datagrams"))
	}
	s, e := conn.OpenStreamSync(ctx)
	if e != nil {
		return fail(e)
	}
	defer s.Close()
	defer s.CancelRead(0)
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	s.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { s.CancelRead(1); s.CancelWrite(1) })
	defer stop()
	authStarted := time.Now()
	if e = protocol.WriteTicket(s, ticket); e != nil {
		return fail(e)
	}
	c := newClient(conn, handshakeMS)
	if conn.ConnectionState().TLS.NegotiatedProtocol == protocol.LeaseALPN {
		ack, err := protocol.ReadLeaseAck(s)
		if err != nil {
			return fail(err)
		}
		if ack.Status != 0 {
			return fail(errors.New("relay rejected ticket"))
		}
		if ack.Sequence != 0 || ack.Duration <= 0 || ack.Duration > 30*time.Minute {
			return fail(errors.New("invalid lease acknowledgement"))
		}
		c.controlReplies = make(chan []byte, 4)
		c.lease = LeaseSnapshot{Supported: true, State: "authorized", Deadline: ack.Deadline, ValidUntil: authStarted.Add(ack.Duration), Duration: ack.Duration}
		s.SetDeadline(time.Time{})
	} else {
		var ack [1]byte
		if _, e = io.ReadFull(s, ack[:]); e != nil || ack[0] != 0 {
			if e == nil {
				e = errors.New("relay rejected ticket")
			}
			return fail(e)
		}
	}
	return c, nil
}
