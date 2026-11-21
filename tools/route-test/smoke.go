package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/internal/e2eprobe"
	"github.com/quic-go/quic-go"
)

func tcpProof(ctx context.Context, o options, client *transport.Client, key []byte, route string) (string, error) {
	attempt, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	var conn net.Conn
	var err error
	if route == "RELAY" {
		conn, err = client.OpenTCP(attempt, netip.MustParseAddrPort(o.tcpTarget))
	} else {
		conn, err = (&net.Dialer{}).DialContext(attempt, "tcp4", o.tcpTarget)
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(o.timeout))
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return "", err
	}
	sent := e2eprobe.Packet{Run: nonce, Sequence: 1}
	raw := e2eprobe.Encode(sent, key)
	for offset := 0; offset < len(raw); {
		n, e := conn.Write(raw[offset:])
		if e != nil {
			return "", e
		}
		if n == 0 {
			return "", io.ErrShortWrite
		}
		offset += n
	}
	response := make([]byte, e2eprobe.Size)
	if _, err = io.ReadFull(conn, response); err != nil {
		return "", err
	}
	reply, err := e2eprobe.Decode(response, key)
	if err != nil || !reply.Reply || reply.Run != sent.Run || reply.Sequence != sent.Sequence || !reply.Peer.IsValid() {
		return "", errors.New("invalid authenticated TCP echo reply")
	}
	return reply.Peer.Addr().String(), nil
}
func rejected(ctx context.Context, o options, a authenticated, ticket []byte) error {
	attempt, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	client, err := transport.DialWithTicket(attempt, o.relay, a.tls, ticket)
	if err == nil {
		client.Close()
		return errors.New("invalid/expired credentials accepted")
	}
	var rejection *quic.ApplicationError
	if err.Error() == "relay rejected ticket" || errors.As(err, &rejection) && rejection.Remote && rejection.ErrorCode == 1 && rejection.ErrorMessage == "ticket rejected" {
		return nil
	}
	return fmt.Errorf("authentication rejection NOT PROVEN (timeout/unavailable is not a rejection): %w", err)
}
func authSmoke(ctx context.Context, o options, a authenticated, result *report) error {
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	valid, err := a.control.Ticket(attempt, o.relayID)
	cancel()
	if err != nil {
		return errors.New("smoke ticket acquisition failed")
	}
	var envelope security.Envelope
	if err := security.Parse(valid, &envelope); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) == 0 {
		return errors.New("invalid ticket signature format")
	}
	signature[0] ^= 1
	envelope.Signature = base64.RawURLEncoding.EncodeToString(signature)
	wrong, _ := json.Marshal(envelope)
	if err := rejected(ctx, o, a, wrong); err != nil {
		return err
	}
	result.Smoke = append(result.Smoke, "wrong ticket credentials rejected PASS")
	var ticket security.Ticket
	if err := security.Verify("ticket", a.keys, valid, &ticket); err != nil {
		return err
	}
	wait := time.Until(ticket.ExpiresAt.Add(time.Second))
	if wait > 5*time.Minute {
		return errors.New("unexpected ticket expiry beyond bounded smoke budget")
	}
	if wait > 0 {
		fmt.Println("Waiting for real signed ticket expiry at", ticket.ExpiresAt.UTC().Format(time.RFC3339), "(no forged expiry)")
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	if err := rejected(ctx, o, a, valid); err != nil {
		return err
	}
	result.Smoke = append(result.Smoke, "real expired unused ticket rejected PASS")
	return nil
}
