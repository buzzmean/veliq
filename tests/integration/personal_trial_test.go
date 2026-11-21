package integration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/quic-go/quic-go"
)

func TestPersonalTrialRelayClampsInitialAndRenewedLease(t *testing.T) {
	x := newLeaseFixture(t, time.Minute, 0)
	deadline := time.Now().Add(2500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	cfg := x.tls.Clone()
	cfg.NextProtos = []string{protocol.LeaseALPN}
	conn, err := quic.DialAddr(ctx, x.server.Addr().String(), cfg, transport.QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test done")
	makeTicket := func() []byte {
		t.Helper()
		id, err := security.NewID()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := security.Sign("ticket", "issuer", x.key, security.Ticket{
			ID: id, DeviceID: "machine", DeviceKey: security.Fingerprint(x.peer), RelayID: "VPS-01",
			IssuedAt: time.Now(), ExpiresAt: deadline, TrialUntil: &deadline,
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(deadline)
	if err = protocol.WriteTicket(stream, makeTicket()); err != nil {
		t.Fatal(err)
	}
	if ack, err := protocol.ReadLeaseAck(stream); err != nil || ack.Status != 0 || !ack.Deadline.Equal(deadline) || ack.Duration <= 0 || ack.Duration > 2500*time.Millisecond {
		t.Fatal("trial lease not capped", ack, err)
	}
	frames, err := protocol.LeaseRequests(1, makeTicket())
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if err = conn.SendDatagram(frame); err != nil {
			t.Fatal(err)
		}
	}
	frame, err := conn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := protocol.ParseLeaseAckFrame(frame); err != nil || ack.Status != 0 || ack.Sequence != 1 || !ack.Deadline.Equal(deadline) {
		t.Fatal("trial renewal extended access", ack, err)
	}
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("server did not end the trial session")
	}
	var closed *quic.ApplicationError
	if err = context.Cause(conn.Context()); !errors.As(err, &closed) || !closed.Remote || closed.ErrorCode != protocol.LeaseExpiredCode {
		t.Fatal("wrong expiration reason", err)
	}
	select {
	case <-x.client.Done():
		t.Fatal("trial expiry also closed an unrelated paid session")
	default:
	}
}

func TestPersonalTrialTicketRejectsBeyondDeadline(t *testing.T) {
	x := newLeaseFixture(t, time.Minute, 0)
	now := time.Now()
	trialUntil := now.Add(time.Second)
	raw, err := security.Sign("ticket", "issuer", x.key, security.Ticket{
		ID: "invalid-trial-cutoff", DeviceID: "machine", DeviceKey: security.Fingerprint(x.peer), RelayID: "VPS-01",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), TrialUntil: &trialUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	v := security.NewTicketVerifier(map[string]ed25519.PublicKey{"issuer": x.key.Public().(ed25519.PublicKey)}, "VPS-01")
	if _, err = v.Accept(raw, x.peer, now); err == nil {
		t.Fatal("ticket validity exceeded the signed trial deadline")
	}
}
