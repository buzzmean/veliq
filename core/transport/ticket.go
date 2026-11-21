package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/quic-go/quic-go"
	"io"
	"time"
)

func DialWithTicket(ctx context.Context, addr string, t *tls.Config, ticket []byte) (*Client, error) {
	cfg := t.Clone()
	cfg.NextProtos = []string{protocol.LeaseALPN, protocol.TicketALPN}
	start := time.Now()
	conn, e := quic.DialAddr(ctx, addr, cfg, ClientQUICConfig())
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
	c := &Client{handshakeMS: handshakeMS, conn: conn, flows: make(map[uint32]*UDPFlow), done: make(chan struct{})}
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
	go c.receive()
	return c, nil
}
