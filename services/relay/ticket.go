package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/security"
	"time"
)

func (x *session) authenticate() error {
	ctx, cancel := context.WithTimeout(x.conn.Context(), 3*time.Second)
	defer cancel()
	s, e := x.conn.AcceptStream(ctx)
	if e != nil {
		return e
	}
	legacy := x.conn.ConnectionState().TLS.NegotiatedProtocol != protocol.LeaseALPN
	defer s.Close()
	defer s.CancelRead(0)

	s.SetDeadline(time.Now().Add(3 * time.Second))
	raw, e := protocol.ReadTicket(s)
	if e != nil {
		return e
	}
	certs := x.conn.ConnectionState().TLS.PeerCertificates
	if len(certs) < 1 {
		return errors.New("device certificate missing")
	}
	peer, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("Ed25519 device certificate required")
	}
	ticket, e := x.server.config.TicketVerifier.Accept(raw, peer, time.Now())
	if e != nil {
		if legacy {
			s.Write([]byte{1})
		} else {
			_ = protocol.WriteLeaseAck(s, protocol.LeaseAck{Status: 1})
		}
		return e
	}
	x.deviceID = ticket.DeviceID
	x.peerKey = peer
	ack := x.leaseGrant(ticket, time.Now())
	if ack.Duration <= 0 {
		return errors.New("trial access expired")
	}
	x.leaseExpires = ack.Deadline
	x.trialLease = ticket.TrialUntil != nil
	x.leaseChanged = make(chan struct{}, 1)
	if legacy {
		_, e = s.Write([]byte{0})
		return e
	}
	e = protocol.WriteLeaseAck(s, ack)
	if e != nil {
		return e
	}
	s.SetDeadline(time.Time{})
	x.control = make(chan []byte, 16)
	x.wg.Add(1)
	go func() { defer x.wg.Done(); x.renewControl() }()
	return nil
}

func (x *session) leaseDuration() time.Duration {
	if x.server.config.Acceptance != nil {
		return x.server.config.Acceptance.LeaseDuration
	}
	return 30 * time.Minute
}
func (x *session) leaseGrant(ticket security.Ticket, now time.Time) protocol.LeaseAck {
	deadline := now.Add(x.leaseDuration())
	if ticket.TrialUntil != nil && ticket.TrialUntil.Before(deadline) {
		deadline = *ticket.TrialUntil
	}
	return protocol.LeaseAck{Deadline: deadline, Duration: deadline.Sub(now)}
}

func (x *session) renewControl() {
	dropped := 0
	var assembly protocol.LeaseAssembly
	for {
		var frame []byte
		select {
		case <-x.conn.Context().Done():
			return
		case frame = <-x.control:
		}
		message, err := assembly.Add(frame, time.Now())
		if err != nil || message == nil {
			continue
		}
		seq, raw, err := protocol.ReadRenewal(bytes.NewReader(message))
		if err != nil {
			continue
		}
		hash := sha256.Sum256(raw)
		x.mu.Lock()
		now := time.Now()
		ack := protocol.LeaseAck{Status: 1, Sequence: seq}
		if now.Before(x.leaseExpires) && !x.server.config.TicketVerifier.Revoked(x.deviceID) {
			if seq == x.renewalSequence && seq != 0 && hash == x.renewalHash {
				// Receipt retrieval on this same authenticated QUIC connection only. This
				// does not consume a ticket again or extend authorization a second time.
				ack = x.renewalReceipt
				ack.Duration = time.Until(ack.Deadline)
			} else if seq == x.renewalSequence+1 {
				ticket, e := x.server.config.TicketVerifier.AcceptForDevice(raw, x.peerKey, x.deviceID, now)
				now = time.Now()
				grant := x.leaseGrant(ticket, now)
				if e == nil && now.Before(x.leaseExpires) && grant.Duration > 0 {
					ack = grant
					ack.Sequence = seq
					x.leaseExpires = ack.Deadline
					x.trialLease = ticket.TrialUntil != nil
					x.renewalSequence = seq
					x.renewalHash = hash
					x.renewalReceipt = ack
					x.server.Metrics.Renewals.Add(1)
					select {
					case x.leaseChanged <- struct{}{}:
					default:
					}
				}
			}
		}
		if ack.Status != 0 {
			x.server.Metrics.RenewalRejected.Add(1)
		}
		x.mu.Unlock()
		if x.server.config.Acceptance != nil && ack.Status == 0 && dropped < x.server.config.Acceptance.DropRenewalACKs {
			dropped++
			continue
		}
		_ = x.conn.SendDatagram(protocol.LeaseAckFrame(ack))
	}
}
