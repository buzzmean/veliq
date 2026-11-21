package integration

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Destination-leg impairment is deterministic, unprivileged, and carries real UDP.
// It does not model client-relay QUIC loss or claim tc/netem equivalence at IP level.
func TestUDPDestinationDelayAndLoss(t *testing.T) {
	_, client, _ := setup(t, 5*time.Second)
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		i := 0
		for {
			n, a, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			i++
			if i%2 == 0 {
				continue
			}
			time.Sleep(5 * time.Millisecond)
			target.WriteToUDP(buf[:n], a)
		}
	}()
	defer func() { target.Close(); <-done }()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	flow, err := client.OpenUDP(ctx, netip.MustParseAddrPort(target.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	received := 0
	for i := 0; i < 10; i++ {
		payload := []byte(fmt.Sprintf("sequence-%d", i))
		start := time.Now()
		if err = flow.Send(payload); err != nil {
			t.Fatal(err)
		}
		probe, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		b, err := flow.Receive(probe)
		stop()
		if i%2 == 0 {
			if err != nil || string(b) != string(payload) {
				t.Fatalf("delayed delivery %q %v", b, err)
			}
			if time.Since(start) < 5*time.Millisecond {
				t.Fatal("delay not observed")
			}
			received++
		} else if err == nil {
			t.Fatal("expected loss")
		}
	}
	if received != 5 {
		t.Fatal("expected 50 percent observed loss")
	}
	t.Log("real UDP delivered 5/10 with >=5ms destination delay; no application-level retransmission")
}
