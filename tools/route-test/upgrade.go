package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/internal/e2eprobe"
	"github.com/quic-go/quic-go"
)

type upgradeReport struct {
	Pass                  bool        `json:"pass"`
	ALPN                  string      `json:"alpn"`
	DefaultLeaseSeconds   int         `json:"default_lease_seconds"`
	Renewals              int         `json:"renewals"`
	Deadlines             []time.Time `json:"deadlines"`
	TCPStreamID           int64       `json:"tcp_stream_id"`
	UDPFlowID             uint32      `json:"udp_flow_id"`
	TCPSource             string      `json:"tcp_source"`
	UDPSource             string      `json:"udp_source"`
	SameConnection        bool        `json:"same_connection"`
	TicketReplayRejected  bool        `json:"ticket_replay_rejected"`
	WrongTicketRejected   bool        `json:"wrong_ticket_rejected"`
	AnonymousMTLSRejected bool        `json:"anonymous_mtls_rejected"`
	Legacy2               bool        `json:"legacy_2"`
	ReceiptRetry          bool        `json:"receipt_retry"`
	RenewalReplayRejected bool        `json:"renewal_replay_rejected"`
	Error                 string      `json:"error,omitempty"`
}

func rawAuthenticate(ctx context.Context, addr string, cfg *tls.Config, ticket []byte, alpn string) (*quic.Conn, protocol.LeaseAck, error) {
	tc := cfg.Clone()
	tc.NextProtos = []string{alpn}
	c, err := quic.DialAddr(ctx, addr, tc, transport.QUICConfig())
	if err != nil {
		return nil, protocol.LeaseAck{}, err
	}
	fail := func(err error) (*quic.Conn, protocol.LeaseAck, error) {
		c.CloseWithError(0, "probe done")
		return nil, protocol.LeaseAck{}, err
	}
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return fail(err)
	}
	defer s.Close()
	defer s.CancelRead(0)
	s.SetDeadline(time.Now().Add(3 * time.Second))
	if err = protocol.WriteTicket(s, ticket); err != nil {
		return fail(err)
	}
	var ack protocol.LeaseAck
	if alpn == protocol.LeaseALPN {
		ack, err = protocol.ReadLeaseAck(s)
	} else {
		var b [1]byte
		_, err = io.ReadFull(s, b[:])
		ack.Status = b[0]
	}
	if err != nil {
		return fail(err)
	}
	if ack.Status != 0 {
		return fail(errors.New("relay rejected ticket"))
	}
	if c.ConnectionState().TLS.NegotiatedProtocol != alpn {
		return fail(errors.New("incorrect negotiated ALPN"))
	}
	return c, ack, nil
}
func openUpgradeStream(ctx context.Context, c *quic.Conn, kind byte, id uint32, dst string) (*quic.Stream, error) {
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	s.SetDeadline(time.Now().Add(3 * time.Second))
	if err = (protocol.Open{Kind: kind, ID: id, Destination: netip.MustParseAddrPort(dst)}).Write(s); err != nil {
		s.CancelRead(1)
		s.CancelWrite(1)
		return nil, err
	}
	var ack [1]byte
	if _, err = io.ReadFull(s, ack[:]); err != nil || ack[0] != 0 {
		s.CancelRead(1)
		s.CancelWrite(1)
		return nil, fmt.Errorf("probe OPEN rejected/failed: status=%d", ack[0])
	}
	s.SetDeadline(time.Time{})
	return s, nil
}
func renewalReceipt(ctx context.Context, c *quic.Conn, seq uint64, ticket []byte) (protocol.LeaseAck, error) {
	frames, err := protocol.LeaseRequests(seq, ticket)
	if err != nil {
		return protocol.LeaseAck{}, err
	}
	// Identical seq/hash retries retrieve a receipt; never issue a new ticket or
	// replay application data when an ACK is lost. Bound all three attempts.
	for attempt := 0; attempt < 3; attempt++ {
		for _, frame := range frames {
			if err = c.SendDatagram(frame); err != nil {
				return protocol.LeaseAck{}, err
			}
		}
		wait, cancel := context.WithTimeout(ctx, time.Second)
		for {
			raw, e := c.ReceiveDatagram(wait)
			if e != nil {
				cancel()
				break
			}
			ack, e := protocol.ParseLeaseAckFrame(raw)
			if e == nil && ack.Sequence == seq {
				cancel()
				return ack, nil
			}
		}
		if ctx.Err() != nil {
			return protocol.LeaseAck{}, ctx.Err()
		}
	}
	return protocol.LeaseAck{}, errors.New("renewal ACK timeout")
}
func upgradeProof(ctx context.Context, o options, a authenticated, fetch func(context.Context) ([]byte, error), echoKey []byte) (out upgradeReport, err error) {
	ticket, err := fetch(ctx)
	if err != nil {
		return out, errors.New("fresh signed-proof ticket unavailable")
	}
	c, ack, err := rawAuthenticate(ctx, o.relay, a.tls, ticket, protocol.LeaseALPN)
	if err != nil {
		return out, err
	}
	defer c.CloseWithError(0, "upgrade proof complete")
	if ack.Sequence != 0 || ack.Duration != 30*time.Minute {
		return out, errors.New("production authorization lease is not 30 minutes")
	}
	out.ALPN = protocol.LeaseALPN
	out.DefaultLeaseSeconds = 1800
	out.Deadlines = append(out.Deadlines, ack.Deadline)
	tcp, err := openUpgradeStream(ctx, c, protocol.TCP, 1, o.tcpTarget)
	if err != nil {
		return out, err
	}
	defer tcp.Close()
	defer tcp.CancelRead(0)
	udp, err := openUpgradeStream(ctx, c, protocol.UDP, 2, o.target)
	if err != nil {
		return out, err
	}
	defer udp.Close()
	defer udp.CancelRead(0)
	out.TCPStreamID = int64(tcp.StreamID())
	out.UDPFlowID = 2
	var run [16]byte
	if _, err = rand.Read(run[:]); err != nil {
		return out, err
	}
	exchange := func(seq uint32) error {
		packet := e2eprobe.Packet{Run: run, Sequence: seq}
		data := e2eprobe.Encode(packet, echoKey)
		tcp.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.Copy(tcp, bytes.NewReader(data)); err != nil {
			return err
		}
		response := make([]byte, e2eprobe.Size)
		if _, err := io.ReadFull(tcp, response); err != nil {
			return err
		}
		p, err := e2eprobe.Decode(response, echoKey)
		if err != nil || !p.Reply || p.Run != run || p.Sequence != seq || p.Peer.Addr().String() != o.expectedEgress {
			return errors.New("invalid TCP echo / egress source")
		}
		out.TCPSource = p.Peer.Addr().String()
		frame, err := protocol.Encode(2, data)
		if err != nil {
			return err
		}
		if err = c.SendDatagram(frame); err != nil {
			return err
		}
		wait, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var raw []byte
		for {
			raw, err = c.ReceiveDatagram(wait)
			if err != nil {
				return err
			}
			// Delayed idempotent control receipts share QUIC datagrams with UDP.
			// Skip only valid ACK frames; never retry/drop application probes.
			if _, e := protocol.ParseLeaseAckFrame(raw); e != nil {
				break
			}
		}
		id, payload, err := protocol.Decode(raw)
		if err != nil || id != 2 {
			return errors.New("invalid UDP mapping reply")
		}
		p, err = e2eprobe.Decode(payload, echoKey)
		if err != nil || !p.Reply || p.Run != run || p.Sequence != seq || p.Peer.Addr().String() != o.expectedEgress {
			return errors.New("invalid UDP echo / egress source")
		}
		out.UDPSource = p.Peer.Addr().String()
		return nil
	}
	if err = exchange(1); err != nil {
		return out, err
	}
	for seq := uint64(1); seq <= 2; seq++ {
		fresh, e := fetch(ctx)
		if e != nil {
			return out, errors.New("renewal fresh ticket unavailable")
		}
		next, e := renewalReceipt(ctx, c, seq, fresh)
		if e != nil {
			return out, e
		}
		if next.Status != 0 || next.Duration != 30*time.Minute || !next.Deadline.After(ack.Deadline) {
			return out, errors.New("renewal did not extend the same 30-minute authorization")
		}
		ack = next
		out.Renewals++
		out.Deadlines = append(out.Deadlines, next.Deadline)
		if err = exchange(uint32(seq + 1)); err != nil {
			return out, err
		}
		receipt, e := renewalReceipt(ctx, c, seq, fresh)
		if e != nil || receipt.Status != 0 || !receipt.Deadline.Equal(next.Deadline) {
			return out, errors.New("same-session receipt retry failed or extended authorization twice")
		}
		out.ReceiptRetry = true
		replay, e := renewalReceipt(ctx, c, seq+1, fresh)
		if e != nil || replay.Status == 0 {
			return out, errors.New("renewal ticket replay was not rejected")
		}
		out.RenewalReplayRejected = true
	}
	out.SameConnection = true
	if err = rejected(ctx, o, a, ticket); err != nil {
		return out, err
	}
	out.TicketReplayRejected = true
	var env security.Envelope
	if err = security.Parse(ticket, &env); err != nil {
		return out, err
	}
	sig, e := base64.RawURLEncoding.DecodeString(env.Signature)
	if e != nil || len(sig) == 0 {
		return out, errors.New("invalid ticket signature")
	}
	sig[0] ^= 1
	env.Signature = base64.RawURLEncoding.EncodeToString(sig)
	wrong, _ := json.Marshal(env)
	if err = rejected(ctx, o, a, wrong); err != nil {
		return out, err
	}
	out.WrongTicketRejected = true
	anonymous := a.tls.Clone()
	anonymous.Certificates = nil
	anonymous.GetClientCertificate = nil
	_, _, e = rawAuthenticate(ctx, o.relay, anonymous, ticket, protocol.LeaseALPN)
	var tlsReject *quic.TransportError
	if !errors.As(e, &tlsReject) || !tlsReject.Remote || tlsReject.ErrorCode < 0x100 || tlsReject.ErrorCode > 0x1ff {
		return out, errors.New("anonymous mTLS rejection NOT proven")
	}
	out.AnonymousMTLSRejected = true
	legacyTicket, e := fetch(ctx)
	if e != nil {
		return out, e
	}
	legacy, _, e := rawAuthenticate(ctx, o.relay, a.tls, legacyTicket, protocol.TicketALPN)
	if e != nil {
		return out, e
	}
	legacy.CloseWithError(0, "legacy probe complete")
	out.Legacy2 = true
	out.Pass = true
	return out, nil
}

func upgradeCommand(parent context.Context, o options) int {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	out := upgradeReport{}
	var err error
	ip, e := netip.ParseAddr(o.expectedEgress)
	if e != nil || !ip.Is4() || o.tcpTarget == "" || o.enrollToken != "" {
		err = errors.New("upgrade check requires existing identity, TCP target, expected IPv4 egress; enrollment is forbidden")
	} else {
		var a authenticated
		a, err = authenticate(ctx, o)
		if err == nil {
			var key []byte
			key, err = e2eprobe.Token(o.echoToken)
			if err == nil {
				out, err = upgradeProof(ctx, o, a, func(ctx context.Context) ([]byte, error) { return a.control.Ticket(ctx, o.relayID) }, key)
			}
		}
	}
	if err != nil {
		out.Pass = false
		out.Error = err.Error()
	}
	raw, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(raw))
	if o.report != "" {
		if e := os.WriteFile(o.report, raw, 0600); e != nil {
			return 1
		}
	}
	if !out.Pass {
		return 1
	}
	return 0
}
