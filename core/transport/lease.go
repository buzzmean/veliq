package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/buzzmean/veliq/core/protocol"
	"github.com/quic-go/quic-go"
)

type LeaseSnapshot struct {
	Supported      bool          `json:"supported"`
	Deadline       time.Time     `json:"server_deadline"`
	ValidUntil     time.Time     `json:"local_deadline"`
	Duration       time.Duration `json:"duration_ns"`
	Renewals       uint64        `json:"renewals"`
	Attempts       uint64        `json:"attempts"`
	Failures       uint64        `json:"failures"`
	ReceiptRetries uint64        `json:"receipt_retries"`
	LastError      string        `json:"last_error,omitempty"`
	State          string        `json:"state"`
}

func (c *Client) Lease() LeaseSnapshot { c.leaseMu.Lock(); defer c.leaseMu.Unlock(); return c.lease }
func (c *Client) Renewable() bool      { return c.controlReplies != nil }

// StartRenewal owns bounded QUIC DATAGRAM control, independent of application stream credit.
// No application data is moved/retried. Fetch must honor its context.
func (c *Client) StartRenewal(fetch func(context.Context) ([]byte, error)) {
	if fetch == nil || !c.Renewable() {
		return
	}
	c.renewalOnce.Do(func() {
		c.controlSend = make(chan struct{}, 1)
		c.leaseChanged = make(chan struct{}, 1)
		go c.leaseWatchdog()
		go c.renew(fetch)
	})
}
func (c *Client) renew(fetch func(context.Context) ([]byte, error)) {
	var sequence uint64
	var pending []byte
	var pendingSince time.Time
	for {
		lease := c.Lease()
		remaining := time.Until(lease.ValidUntil)
		if remaining <= 0 {
			c.leaseMu.Lock()
			c.lease.State = "expired"
			c.leaseMu.Unlock()
			c.rememberEndReason("authorization_lease_expired")
			c.conn.CloseWithError(protocol.ClientLeaseExpiredCode, "authorization_lease_expired")
			return
		}
		wait := time.Duration(0)
		if len(pending) == 0 && lease.LastError == "" {
			var b [8]byte
			_, _ = rand.Read(b[:])
			jitter := time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(max(time.Millisecond, lease.Duration/20)))
			wait = remaining - lease.Duration/3 - jitter
		} else {
			wait = min(10*time.Second, max(20*time.Millisecond, lease.Duration/30))
		}
		wait = max(0, min(wait, remaining))
		timer := time.NewTimer(wait)
		select {
		case <-c.conn.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		lease = c.Lease()
		remaining = time.Until(lease.ValidUntil)
		if remaining <= 0 {
			continue
		}
		budget := min(3*time.Second, min(remaining, max(30*time.Millisecond, lease.Duration/10)))
		ctx, cancel := context.WithTimeout(c.conn.Context(), budget)
		c.leaseMu.Lock()
		c.lease.Attempts++
		c.lease.State = "renewing"
		c.leaseMu.Unlock()
		var err error
		if len(pending) == 0 {
			pending, err = fetch(ctx)
			if err == nil {
				pendingSince = time.Now()
				sequence++
			}
		}
		if err == nil {
			started := pendingSince
			frames, e := protocol.LeaseRequests(sequence, pending)
			err = e
			if err == nil {
				err = c.sendLease(ctx, frames)
			}
			var ack protocol.LeaseAck
			if err == nil {
				for {
					select {
					case <-ctx.Done():
						err = ctx.Err()
					case raw := <-c.controlReplies:
						ack, err = protocol.ParseLeaseAckFrame(raw)
					}
					if err != nil || ack.Sequence >= sequence {
						break
					}
				}
				if err == nil && (ack.Sequence != sequence || ack.Status != 0 || ack.Duration <= 0 || ack.Duration > 30*time.Minute) {
					err = errors.New("renewal_rejected")
				}
			}
			if err == nil {
				c.leaseMu.Lock()
				if c.lease.State == "expired" || c.conn.Context().Err() != nil {
					c.leaseMu.Unlock()
					cancel()
					return
				}
				c.lease.Deadline = ack.Deadline
				c.lease.ValidUntil = started.Add(ack.Duration)
				c.lease.Renewals++
				c.lease.LastError = ""
				c.lease.State = "authorized"
				c.leaseMu.Unlock()
				select {
				case c.leaseChanged <- struct{}{}:
				default:
				}
				pending = nil
			} else {
				c.leaseMu.Lock()
				c.lease.ReceiptRetries++
				c.leaseMu.Unlock()
			}
		}
		cancel()
		if err != nil {
			c.leaseMu.Lock()
			c.lease.Failures++
			detail := fmt.Sprint(err)
			if len(detail) > 256 {
				detail = detail[:256]
			}
			c.lease.LastError = detail
			if c.conn.Context().Err() == nil {
				c.lease.State = "retrying"
			}
			c.leaseMu.Unlock()
		}
	}
}

// Publish a terminal reason before Done. QUIC may close its DATAGRAM reader
// before its Context cancellation cause is observable to another goroutine.
func (c *Client) rememberEndReason(reason string) {
	c.endReason.CompareAndSwap(nil, &sessionEnd{reason})
}
func (c *Client) SessionEndReason() string {
	if end := c.endReason.Load(); end != nil && (end.reason == "authorization_lease_expired" || end.reason == "device_revoked") {
		return end.reason
	}
	err := context.Cause(c.conn.Context())
	if reason := AuthorizationEndReason(err); reason != "" {
		return reason
	}
	if end := c.endReason.Load(); end != nil {
		return end.reason
	}
	if err != nil {
		return "session_transport_closed"
	}
	return ""
}

// AuthorizationEndReason distinguishes policy expiry/revocation from transport faults.
func AuthorizationEndReason(err error) string {
	var app *quic.ApplicationError
	if errors.As(err, &app) {
		switch app.ErrorCode {
		case protocol.LeaseExpiredCode, protocol.ClientLeaseExpiredCode:
			return "authorization_lease_expired"
		case protocol.RevokedCode:
			return "device_revoked"
		}
	}
	return ""
}

// QUIC's DATAGRAM enqueue can wait behind network congestion. One bounded sender
// per session honors caller timeouts without spawning unbounded blocked writers.
func (c *Client) sendLease(ctx context.Context, frames [][]byte) error {
	select {
	case c.controlSend <- struct{}{}:
	default:
		return errors.New("renewal_send_pending")
	}
	done := make(chan error, 1)
	go func() {
		defer func() { <-c.controlSend }()
		for _, frame := range frames {
			if err := ctx.Err(); err != nil {
				done <- err
				return
			}
			if err := c.conn.SendDatagram(frame); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Client) leaseWatchdog() {
	for {
		lease := c.Lease()
		timer := time.NewTimer(max(0, time.Until(lease.ValidUntil)))
		select {
		case <-c.conn.Context().Done():
			timer.Stop()
			return
		case <-c.leaseChanged:
			timer.Stop()
			continue
		case <-timer.C:
		}
		c.leaseMu.Lock()
		if !time.Now().Before(c.lease.ValidUntil) {
			c.lease.State = "expired"
			c.rememberEndReason("authorization_lease_expired")
			c.conn.CloseWithError(protocol.ClientLeaseExpiredCode, "authorization_lease_expired")
			c.leaseMu.Unlock()
			return
		}
		c.leaseMu.Unlock()
	}
}
