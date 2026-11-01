package windowsplatform

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/routing"
	quic "github.com/quic-go/quic-go"
)

// Independent quic-go client, real UDP loopback, default hybrid key share.
// No synthetic Initial sealer is shared with the observer under test.
func captureQUICOriginFlight(t *testing.T, host string) [][]byte {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	transport := &quic.Transport{Conn: client}
	defer transport.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := transport.Dial(ctx, listener.LocalAddr(), &tls.Config{ServerName: host, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}, &quic.Config{Versions: []quic.Version{quic.Version1}, InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
		if err == nil {
			conn.CloseWithError(0, "fixture complete")
		}
	}()
	defer func() { cancel(); <-done }()
	listener.SetReadDeadline(time.Now().Add(3 * time.Second))
	var packets [][]byte
	var observer localstrategy.QUICOriginObserver
	for i := 0; i < 8; i++ {
		p := make([]byte, 1500)
		n, _, err := listener.ReadFrom(p)
		if err != nil {
			t.Fatal(err)
		}
		p = p[:n]
		packets = append(packets, p)
		r := observer.Observe(p, time.Now())
		if r.Complete {
			if r.Domain != host || r.Reason != "QUIC_ORIGIN_VISIBLE_SNI" {
				t.Fatal("real QUIC flight not understood", r)
			}
			if len(packets) < 2 {
				t.Fatal("fixture did not exercise segmented hybrid ClientHello")
			}
			return packets
		}
	}
	t.Fatal("too many Initials")
	return nil
}
func quicOriginScopeFixture() (ProcessIdentity, Tuple, Decision) {
	s := quicProbeScopeFixture()
	tuple := Tuple{Protocol: "udp", Source: s.Source, Destination: s.Destination}
	d := Decision{Block: true, BlockOnFailure: true, Revision: s.Revision, Network: s.Network, Flow: routing.Flow{ApplicationID: s.Profile}, Policy: flowpolicy.Result{Action: flowpolicy.Block, Source: "browser_native_quic_tcp_fallback"}}
	return s.Owner, tuple, d
}
func quicOriginPendingCount(p *quicOriginPool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

func TestQUICOriginRealFlightAndScopedPool(t *testing.T) {
	packets := captureQUICOriginFlight(t, "www.youtube.com")
	id, tuple, d := quicOriginScopeFixture()
	now := time.Now()
	var pool quicOriginPool
	defer pool.clear()
	var state quicOriginCaptureState
	for i, p := range packets {
		saved := bytes.Clone(p)
		r, publish := pool.observe(&state, id, tuple, d, p, i == 0, now)
		if !bytes.Equal(p, saved) {
			t.Fatal("mutated datagram")
		}
		if i == 0 && (!publish || r.Complete || r.Domain != "") {
			t.Fatal("partial observation contract", r)
		}
		if i == len(packets)-1 && (!publish || r.Domain != "www.youtube.com") {
			t.Fatal(r)
		}
	}
	if quicOriginPendingCount(&pool) != 0 {
		t.Fatal("completed buffer retained")
	}
	if _, publish := pool.observe(&state, id, tuple, d, packets[0], false, now); publish {
		t.Fatal("duplicate publication")
	}
	for _, mutate := range []func(*ProcessIdentity, *Tuple, *Decision){
		func(id *ProcessIdentity, _ *Tuple, _ *Decision) { id.CreationTime++ },
		func(_ *ProcessIdentity, t *Tuple, _ *Decision) { t.Source = netip.MustParseAddrPort("127.0.0.1:50002") },
		func(_ *ProcessIdentity, _ *Tuple, d *Decision) { d.Revision = "changed" },
		func(_ *ProcessIdentity, _ *Tuple, d *Decision) { d.Network = "changed" },
		func(_ *ProcessIdentity, _ *Tuple, d *Decision) { d.Flow.ApplicationID = "changed" },
	} {
		var s quicOriginCaptureState
		pool.observe(&s, id, tuple, d, packets[0], true, now)
		changedID, changedTuple, changedDecision := id, tuple, d
		mutate(&changedID, &changedTuple, &changedDecision)
		r, publish := pool.observe(&s, changedID, changedTuple, changedDecision, packets[1], false, now)
		if !publish || r.Domain != "" || r.Reason != "QUIC_ORIGIN_SCOPE_CHANGED" || quicOriginPendingCount(&pool) != 0 {
			t.Fatal("stale scope published/retained", r)
		}
		if r, publish := pool.observe(&s, id, tuple, d, packets[1], false, now); publish || r.Domain != "" {
			t.Fatal("revived scope")
		}
	}
}
func TestQUICOriginPoolCapacityDeadlineAndRate(t *testing.T) {
	packets := captureQUICOriginFlight(t, "www.youtube.com")
	id, tuple, d := quicOriginScopeFixture()
	now := time.Now()
	var pool quicOriginPool
	defer pool.clear()
	states := make([]quicOriginCaptureState, quicOriginPendingLimit+1)
	for i := range states {
		r, _ := pool.observe(&states[i], id, tuple, d, packets[0], true, now)
		if i == quicOriginPendingLimit && r.Reason != "QUIC_ORIGIN_CAPACITY" {
			t.Fatal(r)
		}
	}
	if quicOriginPendingCount(&pool) != quicOriginPendingLimit {
		t.Fatal("capacity escaped")
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		pool.mu.Lock()
		pending := len(pool.pending)
		pool.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inactive buffers not expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r, publish := pool.observe(&states[0], id, tuple, d, packets[1], false, time.Now())
	if !publish || r.Domain != "" || r.Reason != "QUIC_ORIGIN_TIMEOUT" {
		t.Fatal(r)
	}
	// Finished or rejected states cannot consume unlimited crypto work per second.
	var rate quicOriginPool
	defer rate.clear()
	for i := 0; i < 65; i++ {
		var s quicOriginCaptureState
		r, _ := rate.observe(&s, id, tuple, d, []byte{0}, true, now)
		if i == 64 && r.Reason != "QUIC_ORIGIN_RATE_LIMIT" {
			t.Fatal(r)
		}
	}
}
func TestQUICOriginDiagnosticIsHistoricalMetadataOnly(t *testing.T) {
	id, tuple, d := quicOriginScopeFixture()
	var ingress captureIngress
	ingress.recordQUICOrigin(id, tuple, d, localstrategy.QUICOriginObservation{Domain: "api.openai.com", Reason: "QUIC_ORIGIN_VISIBLE_SNI", Complete: true})
	s := ingress.snapshot(id.PID)
	if len(s.Records) != 1 || s.Records[0].Decision != "UDP443_BLOCK" || s.Records[0].Network != d.Network || s.Records[0].PolicyRevision != d.Revision || d.OriginDomain != "" || !d.Block {
		t.Fatal("metadata turned into routing")
	}
	s.Records[0].QUICOrigin.Domain = "changed"
	if ingress.snapshot(id.PID).Records[0].QUICOrigin.Domain != "api.openai.com" {
		t.Fatal("mutable snapshot alias")
	}
}
