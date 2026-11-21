package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/internal/e2eprobe"
)

func TestUpgradeProofRealProductionLeaseImmediateRenewals(t *testing.T) {
	o, a, _, key, issuer := testRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go e2eprobe.ServeTCP(ctx, tcp, key, &e2eprobe.EchoStats{})
	go e2eprobe.Serve(ctx, udp, key, &e2eprobe.EchoStats{})
	o.tcpTarget = tcp.Addr().String()
	o.target = udp.LocalAddr().String()
	o.expectedEgress = "127.0.0.1"
	var issued int
	fetch := func(ctx context.Context) ([]byte, error) {
		issued++
		// A fresh one-shot ticket needs a unique ID even when Windows returns
		// identical wall-clock readings. Space immediate renewals beyond one
		// coarse clock tick so strict deadline-extension assertions stay real.
		if issued > 1 {
			select {
			case <-time.After(20 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return testTicket(t, issuer, a.tls, fmt.Sprintf("upgrade-ticket-%d", issued), time.Now().Add(time.Minute)), nil
	}
	started := time.Now()
	r, err := upgradeProof(ctx, o, a, fetch, key)
	if err != nil {
		t.Fatal(err, r)
	}
	if !r.Pass || r.Renewals != 2 || !r.SameConnection || !r.TicketReplayRejected || !r.WrongTicketRejected || !r.AnonymousMTLSRejected || !r.Legacy2 || !r.ReceiptRetry || !r.RenewalReplayRejected || r.DefaultLeaseSeconds != 1800 || issued != 4 || len(r.Deadlines) != 3 {
		t.Fatal(r, issued)
	}
	if time.Since(started) > 15*time.Second {
		t.Fatal("unexpected long wait")
	}
	t.Logf("real mTLS /3, two immediate 30-minute renewals, same TCP/UDP, replay + legacy /2; elapsed %v", time.Since(started))
}
