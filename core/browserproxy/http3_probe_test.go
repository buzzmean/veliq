package browserproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

func http3ProbeKeyFixture() HTTP3ProbeKey {
	return HTTP3ProbeKey{Host: "www.youtube.com", Endpoint: netip.MustParseAddrPort("74.125.111.131:443"), PID: 1, Birth: 2, Executable: `C:\Fixture\chrome.exe`, Network: "network", Profile: "profile", Revision: "revision"}
}

func TestHTTP3ProbeScopeRejectsBeforeOpening(t *testing.T) {
	m := NewHTTP3ProbeManager()
	defer m.Close()
	for _, mutate := range []func(*HTTP3ProbeKey){
		func(k *HTTP3ProbeKey) { k.Host = "api.openai.com" },
		func(k *HTTP3ProbeKey) { k.Host = "example.com" },
		func(k *HTTP3ProbeKey) { k.Host = "www.youtube.com/secret" },
		func(k *HTTP3ProbeKey) { k.Endpoint = netip.MustParseAddrPort("127.0.0.1:443") },
		func(k *HTTP3ProbeKey) { k.Endpoint = netip.MustParseAddrPort("[2606:4700::1111]:443") },
		func(k *HTTP3ProbeKey) { k.Endpoint = netip.MustParseAddrPort("74.125.111.131:80") },
		func(k *HTTP3ProbeKey) { k.PID = 0 }, func(k *HTTP3ProbeKey) { k.Birth = 0 },
		func(k *HTTP3ProbeKey) { k.Network = "" }, func(k *HTTP3ProbeKey) { k.Profile = "" },
		func(k *HTTP3ProbeKey) { k.Revision = "" }, func(k *HTTP3ProbeKey) { k.Executable = "" },
	} {
		key := http3ProbeKeyFixture()
		mutate(&key)
		r := m.Probe(context.Background(), key, nil, func(HTTP3ProbeKey) bool { return true }, func(context.Context) (HTTP3ProbeSocket, error) { t.Fatal("opened invalid scope"); return nil, nil })
		if r.Observed || r.Outcome != "HTTP3_SCOPE_INVALID" {
			t.Fatal(r)
		}
	}
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		r := m.Probe(ctx, http3ProbeKeyFixture(), nil, func(HTTP3ProbeKey) bool { return canceled }, func(context.Context) (HTTP3ProbeSocket, error) {
			t.Fatal("opened stale/canceled scope")
			return nil, nil
		})
		cancel()
		if r.Observed || r.Outcome != "HTTP3_SCOPE_CHANGED" && r.Outcome != "HTTP3_CANCELED_OR_TIMEOUT" {
			t.Fatal(r)
		}
	}
}

func TestHTTP3ProbeManagerNoQueueAndCloseCancelsOpen(t *testing.T) {
	m := NewHTTP3ProbeManager()
	defer m.Close()
	current := func(HTTP3ProbeKey) bool { return true }
	entered := make(chan struct{})
	done := make(chan HTTP3ProbeResult, 1)
	go func() {
		done <- m.Probe(context.Background(), http3ProbeKeyFixture(), nil, current, func(ctx context.Context) (HTTP3ProbeSocket, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	<-entered
	noOpen := func(context.Context) (HTTP3ProbeSocket, error) { t.Fatal("extra socket opened"); return nil, nil }
	if r := m.Probe(context.Background(), http3ProbeKeyFixture(), nil, current, noOpen); r.Outcome != "HTTP3_BUSY" {
		t.Fatal(r)
	}
	m.Close()
	if r := <-done; r.Observed || r.Outcome != "HTTP3_CANCELED_OR_TIMEOUT" {
		t.Fatal(r)
	}
	if r := m.Probe(context.Background(), http3ProbeKeyFixture(), nil, current, noOpen); r.Outcome != "HTTP3_MANAGER_CLOSED" {
		t.Fatal(r)
	}
}

type http3MeterFixture struct {
	net.PacketConn
	peer   net.Addr
	size   int
	writes atomic.Int64
}

func (f *http3MeterFixture) ReadFrom(p []byte) (int, net.Addr, error) {
	return min(len(p), f.size), f.peer, nil
}
func (f *http3MeterFixture) WriteTo(p []byte, _ net.Addr) (int, error) {
	f.writes.Add(1)
	return len(p), nil
}

func TestHTTP3ProbeDatagramBudgetAndPeer(t *testing.T) {
	peer := http3ProbeKeyFixture().Endpoint
	addr := net.UDPAddrFromAddrPort(peer)
	for _, size := range []int{0, 1500} {
		f := &http3MeterFixture{peer: addr, size: size}
		m := &http3ProbeMeter{PacketConn: f, peer: peer}
		for i := 0; i <= HTTP3ProbeReceivePackets; i++ {
			_, _, err := m.ReadFrom(make([]byte, 2000))
			if err != nil {
				if !errors.Is(err, errHTTP3ProbeBudget) {
					t.Fatal(err)
				}
				break
			}
		}
		if !m.limited.Load() || m.received.Load() > HTTP3ProbeReceiveLimit || m.receivedPackets.Load() > HTTP3ProbeReceivePackets {
			t.Fatal("RX budget escaped")
		}
	}
	for _, size := range []int{0, 1200} {
		f := &http3MeterFixture{peer: addr}
		m := &http3ProbeMeter{PacketConn: f, peer: peer}
		var workers sync.WaitGroup
		for i := 0; i < 300; i++ {
			workers.Add(1)
			go func() { defer workers.Done(); m.WriteTo(make([]byte, size), addr) }()
		}
		workers.Wait()
		if !m.limited.Load() || m.sent.Load() > HTTP3ProbeSendLimit || m.sentPackets.Load() > HTTP3ProbeSendPackets || uint64(f.writes.Load()) != m.sentPackets.Load() {
			t.Fatal("concurrent TX budget escaped")
		}
	}
	f := &http3MeterFixture{peer: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("74.125.111.132:443"))}
	m := &http3ProbeMeter{PacketConn: f, peer: peer}
	if _, _, err := m.ReadFrom(make([]byte, 1500)); err == nil {
		t.Fatal("unexpected RX peer accepted")
	}
	if _, err := m.WriteTo([]byte{1}, f.peer); err == nil || f.writes.Load() != 0 {
		t.Fatal("unexpected TX peer accepted")
	}
	if _, err := m.WriteTo(make([]byte, 1473), addr); err == nil || f.writes.Load() != 0 {
		t.Fatal("oversized datagram accepted")
	}
}
