package main

import (
	"bytes"
	"context"
	"github.com/buzzmean/neexitlag/internal/e2eprobe"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNormalSocketClientReportsRealTraffic(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	server, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e2eprobe.Serve(ctx, server, key, &e2eprobe.EchoStats{})
	r, e := run(netip.MustParseAddrPort(server.LocalAddr().String()), key, 5, 20*time.Millisecond, 100*time.Millisecond, true)
	if e != nil || r.Sent != 5 || r.Received != 5 || r.Loss != 0 || r.RTTMS < 0 || r.Exe == "" || r.PID == 0 || len(r.ObservedSources) != 1 || r.ObservedSources[0] != "127.0.0.1" {
		t.Fatal(r, e)
	}
}

func TestWarmupUsesSameSocketAndDoesNotHideMeasuredLoss(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan struct{})
	var endpoints []string
	go func() {
		defer close(done)
		var warmRun [16]byte
		var late []byte
		buf := make([]byte, e2eprobe.Size+1)
		for i := 0; i < 6; i++ {
			server.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, peer, err := server.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			endpoints = append(endpoints, peer.String())
			p, err := e2eprobe.Decode(buf[:n], key)
			if err != nil {
				return
			}
			if i == 0 {
				warmRun = p.Run
			}
			p.Reply = true
			p.Peer = peer
			response := e2eprobe.Encode(p, key)
			if p.Run == warmRun {
				late = response
			} else {
				// A late authenticated warm-up reply must not count in measurement.
				server.WriteToUDPAddrPort(late, peer)
				if p.Sequence == 2 {
					continue
				} // Deliberate fixture loss must stay visible.
			}
			server.WriteToUDPAddrPort(response, peer)
		}
	}()
	r, err := runWithWarmup(netip.MustParseAddrPort(server.LocalAddr().String()), key, 3, 3, 20*time.Millisecond, 60*time.Millisecond, true)
	<-done
	if err != nil || r.Warmup == nil || r.Warmup.Sent != 3 || r.Warmup.Received != 3 || r.Sent != 3 || r.Received != 2 || r.Loss < 0.33 || r.Run == r.Warmup.Run {
		t.Fatal(r, err)
	}
	if len(endpoints) != 6 {
		t.Fatal("missing datagrams")
	}
	for _, endpoint := range endpoints {
		if endpoint != endpoints[0] {
			t.Fatal("warm-up did not retain the process socket")
		}
	}
	if !r.MeasurementStarted.After(r.Warmup.MeasurementFinished) || !r.MeasurementFinished.After(r.MeasurementStarted) {
		t.Fatal("invalid measurement windows")
	}
}
