package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

// This tunnel-side bridge sees the actual client UDP source ports. It can keep
// the first path alive during validation and silently blackhole it afterwards.
// The existing authenticated relay still opens and owns both origin sockets.
type pathBridge struct {
	gate       *net.UDPConn
	first      atomic.Uint32
	blocked    atomic.Uint32
	blackhole  atomic.Bool
	last       atomic.Uint32
	replyPath  atomic.Uint32
	firstDelay atomic.Int64
	stop       chan struct{}
}

func newPathBridge(t *testing.T, dst *net.UDPAddr) *pathBridge {
	t.Helper()
	gate, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b := &pathBridge{gate: gate, stop: make(chan struct{})}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(b.stop)
		_ = gate.Close()
		<-done
	})
	go func() {
		defer close(done)
		upstreams := map[uint16]*net.UDPConn{}
		defer func() {
			for _, upstream := range upstreams {
				_ = upstream.Close()
			}
		}()
		var packet [2048]byte
		for {
			n, src, err := gate.ReadFromUDPAddrPort(packet[:])
			if err != nil {
				return
			}
			b.first.CompareAndSwap(0, uint32(src.Port()))
			if uint32(src.Port()) == b.blocked.Load() || b.blackhole.Load() && uint32(src.Port()) == b.first.Load() {
				continue
			}
			upstream := upstreams[src.Port()]
			if upstream == nil {
				upstream, err = net.DialUDP("udp4", nil, dst)
				if err != nil {
					t.Error(err)
					return
				}
				upstreams[src.Port()] = upstream
				go b.reply(upstream, src)
			}
			if _, err := upstream.Write(packet[:n]); err == nil {
				b.last.Store(uint32(src.Port()))
			}
		}
	}()
	return b
}

func (b *pathBridge) reply(upstream *net.UDPConn, src netip.AddrPort) {
	var packet [2048]byte
	for {
		n, err := upstream.Read(packet[:])
		if err != nil {
			return
		}
		select {
		case <-b.stop:
			return
		default:
		}
		if !b.blackhole.Load() || uint32(src.Port()) != b.first.Load() {
			if uint32(src.Port()) == b.first.Load() {
				time.Sleep(time.Duration(b.firstDelay.Load()))
			}
			b.replyPath.Store(uint32(src.Port()))
			_, _ = b.gate.WriteToUDPAddrPort(packet[:n], src)
		}
	}
}

func TestSameRelayPathKeepsAuthenticatedTCPAndUDP(t *testing.T) {
	serverTLS, clientTLS, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	issuer, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayServer, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: serverTLS,
		TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"issuer": issuer}, "lab-relay"),
		Allow:          []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	defer relayServer.Close()
	bridge := newPathBridge(t, relayServer.Addr().(*net.UDPAddr))
	device := clientTLS.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	now := time.Now()
	ticket, err := security.Sign("ticket", "issuer", key, security.Ticket{ID: "path-handover-once", DeviceID: "lab-client", DeviceKey: security.Fingerprint(device),
		RelayID: "lab-relay", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	client, err := transport.DialWithTicketPathMigration(ctx, bridge.gate.LocalAddr().String(), clientTLS, ticket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	lease := client.Lease()
	if !lease.Supported || lease.State != "authorized" {
		t.Fatalf("missing authenticated lease: %+v", lease)
	}

	tcpOrigin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpOrigin.Close()
	tcpPeers := make(chan string, 2)
	go func() {
		for {
			conn, err := tcpOrigin.Accept()
			if err != nil {
				return
			}
			tcpPeers <- conn.RemoteAddr().String()
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	udpOrigin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpOrigin.Close()
	udpPeers := make(chan netip.AddrPort, 16)
	go func() {
		var packet [64]byte
		for {
			n, src, err := udpOrigin.ReadFromUDPAddrPort(packet[:])
			if err != nil {
				return
			}
			udpPeers <- src
			_, _ = udpOrigin.WriteToUDPAddrPort(packet[:n], src)
		}
	}()

	conn, err := client.OpenTCP(ctx, netip.MustParseAddrPort(tcpOrigin.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	udp, err := client.OpenUDP(ctx, udpOrigin.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcpID := conn.(interface{ StreamID() int64 }).StreamID()
	udpID := udp.FlowID()
	var tcpPeer string
	select {
	case tcpPeer = <-tcpPeers:
	case <-ctx.Done():
		t.Fatal("initial TCP origin socket not opened")
	}
	tcpEcho := func(seq uint64) {
		t.Helper()
		payload := binary.BigEndian.AppendUint64(nil, seq)
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write %d on existing TCP stream: %v", seq, err)
		}
		reply := make([]byte, 8)
		if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("read %d on existing TCP stream: %x, %v", seq, reply, err)
		}
	}
	udpEcho := func(seq uint64) netip.AddrPort {
		t.Helper()
		payload := binary.BigEndian.AppendUint64(nil, seq)
		if err := udp.Send(payload); err != nil {
			t.Fatalf("send %d on existing UDP flow: %v", seq, err)
		}
		got, err := udp.Receive(ctx)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("receive %d on existing UDP flow: %x, %v", seq, got, err)
		}
		return <-udpPeers
	}
	tcpEcho(0)
	udpPeer := udpEcho(0)
	incumbent := bridge.first.Load()
	if incumbent == 0 {
		t.Fatal("bridge did not observe incumbent UDP port")
	}

	blockedSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	blockedBind := blockedSocket.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = blockedSocket.Close()
	bridge.blocked.Store(uint32(blockedBind.Port()))
	failedProbe, stop := context.WithTimeout(ctx, 120*time.Millisecond)
	admit := func(transport.RelayPathChange) bool { return true }
	_, err = client.SwitchSameRelayPath(failedProbe, blockedBind, admit)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unvalidated alternate should time out without switching: %v", err)
	}
	tcpEcho(1)
	if got := udpEcho(1); got != udpPeer || bridge.last.Load() != incumbent {
		t.Fatalf("failed probe disturbed incumbent: route=%d, origin=%v", bridge.last.Load(), got)
	}
	didValidate := false
	_, err = client.SwitchSameRelayPath(ctx, netip.MustParseAddrPort("127.0.0.1:0"), func(transport.RelayPathChange) bool {
		didValidate = true
		return false
	})
	if err == nil || !didValidate {
		t.Fatalf("validation must not bypass final admission: %v", err)
	}
	tcpEcho(2)
	if got := udpEcho(2); got != udpPeer || bridge.last.Load() != incumbent {
		t.Fatalf("denied switch disturbed incumbent: route=%d, origin=%v", bridge.last.Load(), got)
	}
	// Give the incumbent a controlled 40 ms delay on relay-to-client packets.
	// Both measurements use the same numbered TCP echo stream to the origin.
	const injectedDelay = 40 * time.Millisecond
	bridge.firstDelay.Store(int64(injectedDelay))
	measure := func(first uint64, path uint32) time.Duration {
		t.Helper()
		var samples [3]time.Duration
		for i := range samples {
			started := time.Now()
			tcpEcho(first + uint64(i))
			samples[i] = time.Since(started)
			if bridge.replyPath.Load() != path {
				t.Fatalf("TCP echo reached client on port %d, expected %d", bridge.replyPath.Load(), path)
			}
		}
		return samples[0] + samples[1] + samples[2]
	}
	before := measure(3, incumbent) / 3
	if before < injectedDelay {
		t.Fatalf("incumbent impairment not observed: %s", before)
	}

	start := time.Now()
	change, err := client.SwitchSameRelayPath(ctx, netip.MustParseAddrPort("127.0.0.1:0"), admit)
	if err != nil || uint32(change.Local.Port()) == incumbent {
		t.Fatalf("alternate not validated: %+v, %v", change, err)
	}
	// Leave the incumbent up until existing payload returns over the new path.
	// A probe alone is not migration proof or permission to cut off the old path.
	tcpEcho(6)
	if bridge.last.Load() != uint32(change.Local.Port()) || bridge.replyPath.Load() != uint32(change.Local.Port()) {
		t.Fatal("first TCP round trip did not use the validated path in both directions")
	}
	firstAfterSwitch := time.Since(start)
	// The old path remains available throughout the comparison so the gain is
	// measured under delay, independently of the later blackhole check.
	after := measure(7, uint32(change.Local.Port())) / 3
	if before-after < injectedDelay/2 {
		t.Fatalf("same-stream improvement too small with configured impairment: before %s after %s", before, after)
	}
	bridge.blackhole.Store(true)
	for seq := uint64(3); seq <= 7; seq++ {
		if got := udpEcho(seq); got != udpPeer {
			t.Fatalf("new UDP association at origin: %v, expected %v", got, udpPeer)
		}
		tcpEcho(seq + 7)
	}
	if bridge.last.Load() != uint32(change.Local.Port()) || relayServer.Metrics.Sessions.Load() != 1 || relayServer.Metrics.Flows.Load() != 2 ||
		relayServer.Metrics.TCPConnections.Load() != 1 || len(tcpPeers) != 0 || len(udpPeers) != 0 ||
		client.Lease() != lease || conn.(interface{ StreamID() int64 }).StreamID() != tcpID || udp.FlowID() != udpID {
		t.Fatal("path switch changed the lease, stream, origin sockets, live session or introduced duplicate datagrams")
	}
	if _, err := client.SwitchSameRelayPath(ctx, netip.MustParseAddrPort("127.0.0.1:0"), admit); err == nil {
		t.Fatal("same relay path admission must remain bounded")
	}
	t.Logf("same authenticated QUIC session, ingress UDP ports %d -> %d, unchanged TCP origin peer %s and UDP origin peer %s, validation %s, first TCP echo %s from start of validation, UDP sequence 0–7 echoed once",
		incumbent, change.Local.Port(), tcpPeer, udpPeer, change.ValidationTime.Round(time.Microsecond), firstAfterSwitch.Round(time.Microsecond))
	t.Logf("same TCP stream, three controlled echo round trips per path, %s artificial incumbent delay: mean before %s, after %s", injectedDelay, before.Round(time.Microsecond), after.Round(time.Microsecond))
}
