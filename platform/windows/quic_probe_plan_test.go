package windowsplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/tools/labcert"
	quic "github.com/quic-go/quic-go"
)

func quicProbeScopeFixture() QUICProbeScope {
	return QUICProbeScope{Owner: ProcessIdentity{PID: 123, CreationTime: 456, Path: `C:\Fixture\chrome.exe`}, Source: netip.MustParseAddrPort("127.0.0.1:50001"), Destination: netip.MustParseAddrPort("74.125.111.131:443"), Network: "fixture-network", Profile: "fixture-profile", Revision: "fixture-revision"}
}
func quicProbePacket(scope QUICProbeScope, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	src, dst := scope.Source.Addr().As4(), scope.Destination.Addr().As4()
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], scope.Source.Port())
	binary.BigEndian.PutUint16(p[22:24], scope.Destination.Port())
	binary.BigEndian.PutUint16(p[24:26], uint16(len(payload)+8))
	copy(p[28:], payload)
	return p
}
func quicProbeRawFixture(scope QUICProbeScope) []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	p[4] = 1
	p[5] = 8
	copy(p[6:14], "fixture1")
	p[14] = 8
	copy(p[15:23], "fixture2")
	binary.BigEndian.PutUint16(p[24:26], 0x4000|uint16(len(p)-26))
	return quicProbePacket(scope, p)
}

func TestQUICProbeSendFailureNeverReplaysOrCommitsPartialPlan(t *testing.T) {
	scope := quicProbeScopeFixture()
	original := quicProbeRawFixture(scope)
	for failure := 1; failure <= 7; failure++ {
		w, err := NewQUICProbeWriter(scope, 6, func(QUICProbeScope) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		send := func(p []byte) error {
			calls++
			if calls == failure {
				return errors.New("uncertain send")
			}
			return nil
		}
		if w.Send(original, send) == nil {
			t.Fatal("send failure ignored")
		}
		if w.Send(original, send) == nil || calls != failure {
			t.Fatal("failed writer replayed a datagram")
		}
		e := w.Evidence()
		if e.Committed || !e.Failed || e.OriginalPackets != 0 || e.FakePackets != uint64(failure-1) {
			t.Fatal("partial plan counted as committed", e)
		}
	}
	// Success transforms once; subsequent QUIC datagrams remain byte-identical.
	w, _ := NewQUICProbeWriter(scope, 6, func(QUICProbeScope) bool { return true })
	var sent [][]byte
	send := func(p []byte) error { sent = append(sent, bytes.Clone(p)); return nil }
	if err := w.Send(original, send); err != nil {
		t.Fatal(err)
	}
	later := quicProbePacket(scope, []byte("\x40encrypted-one-rtt"))
	if err := w.Send(later, send); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 8 || !bytes.Equal(sent[6], original) || !bytes.Equal(sent[7], later) || !w.Evidence().Committed || w.Evidence().FakePackets != 6 {
		t.Fatal("cutoff or original changed")
	}
}

func TestQUICProbeCancellationAndTupleBinding(t *testing.T) {
	scope := quicProbeScopeFixture()
	original := quicProbeRawFixture(scope)
	current := true
	w, _ := NewQUICProbeWriter(scope, 6, func(QUICProbeScope) bool { return current })
	if err := w.Send(original, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	current = false
	if e := w.Evidence(); e.Committed || !e.Failed {
		t.Fatal("published stale witness without another send", e)
	}
	current = true
	if w.Evidence().Committed {
		t.Fatal("revoked witness resurrected")
	}
	// Revocation at each send boundary, including after the original succeeded.
	for cancelAfter := 0; cancelAfter <= 7; cancelAfter++ {
		calls := 0
		w, _ := NewQUICProbeWriter(scope, 6, func(s QUICProbeScope) bool { return s == scope && calls < cancelAfter })
		if w.Send(original, func([]byte) error { calls++; return nil }) == nil || calls != cancelAfter || w.Evidence().Committed {
			t.Fatal("revoked scope escaped", cancelAfter, calls, w.Evidence())
		}
	}
	for _, mutate := range []func(*QUICProbeScope){
		func(s *QUICProbeScope) { s.Owner.Path = `C:\Games\TslGame.exe` },
		func(s *QUICProbeScope) { s.Owner.PID = 0 }, func(s *QUICProbeScope) { s.Owner.CreationTime = 0 },
		func(s *QUICProbeScope) { s.Network = "" }, func(s *QUICProbeScope) { s.Profile = "" }, func(s *QUICProbeScope) { s.Revision = "" },
		func(s *QUICProbeScope) { s.Destination = netip.MustParseAddrPort("127.0.0.1:443") },
		func(s *QUICProbeScope) { s.Destination = netip.MustParseAddrPort("74.125.111.131:53") },
	} {
		s := scope
		mutate(&s)
		if _, err := NewQUICProbeWriter(s, 6, func(QUICProbeScope) bool { return true }); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	for _, offset := range []int{12, 16, 20, 22} {
		p := bytes.Clone(original)
		p[offset] ^= 1
		w, _ := NewQUICProbeWriter(scope, 6, func(QUICProbeScope) bool { return true })
		calls := 0
		if w.Send(p, func([]byte) error { calls++; return nil }) == nil || calls != 0 {
			t.Fatal("tuple changed")
		}
	}
}

// The seam replaces capture/injection only: plans contain full IPv4/UDP packets
// and their unchanged payloads traverse a real socket to an isolated QUIC server.
type quicProbeSocket struct {
	net.PacketConn
	scope       QUICProbeScope
	writer      *QUICProbeWriter
	destination net.Addr
	unchanged   atomic.Uint64
}

func (p *quicProbeSocket) WriteTo(payload []byte, dst net.Addr) (int, error) {
	if dst.String() != p.destination.String() {
		return 0, errors.New("fixture destination changed")
	}
	packet := quicProbePacket(p.scope, payload)
	err := p.writer.Send(packet, func(out []byte) error {
		tuple, data, err := ParseUDP(out)
		if err != nil || tuple.Source != p.scope.Source || tuple.Destination != p.scope.Destination {
			return errors.New("invalid planned tuple")
		}
		if bytes.Equal(data, payload) {
			p.unchanged.Add(1)
		}
		n, err := p.PacketConn.WriteTo(data, dst)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func TestQUICProbeAuthenticatedExchange(t *testing.T) {
	owner := quicProbeOwner(t)
	for _, badCertificate := range []bool{false, true} {
		name := "verified-mtls"
		if badCertificate {
			name = "wrong-server-certificate"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			serverTLS, clientTLS, err := labcert.Pair()
			if err != nil {
				t.Fatal(err)
			}
			// Allow the model's ALPN to reach the server TLS parser. It still has
			// no client certificate/Finished and cannot open application streams.
			serverTLS.NextProtos = append(serverTLS.NextProtos, "h3")
			clientTLS.ServerName = "127.0.0.1"
			clientTLS.CurvePreferences = []tls.CurveID{tls.X25519}
			if badCertificate {
				clientTLS.RootCAs = x509.NewCertPool()
			}
			config := &quic.Config{Versions: []quic.Version{quic.Version1}, InitialPacketSize: 1200, DisablePathMTUDiscovery: true, HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 3 * time.Second, MaxIncomingStreams: 2}
			listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, config)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var accepted atomic.Uint64
			served := make(chan error, 1)
			go func() {
				conn, err := listener.Accept(ctx)
				if err != nil {
					served <- err
					return
				}
				accepted.Add(1)
				if len(conn.ConnectionState().TLS.PeerCertificates) == 0 {
					served <- errors.New("missing client certificate")
					return
				}
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					served <- err
					return
				}
				body, err := io.ReadAll(io.LimitReader(stream, 128*1024+1))
				if err != nil {
					served <- err
					return
				}
				digest := sha256.Sum256(body)
				_, err = stream.Write(digest[:])
				if err == nil {
					err = stream.Close()
				}
				served <- err
			}()
			raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			scope := quicProbeScopeFixture()
			scope.Owner = owner
			scope.Source = raw.LocalAddr().(*net.UDPAddr).AddrPort()
			writer, err := NewQUICProbeWriter(scope, 6, func(s QUICProbeScope) bool { return s == scope && (runtime.GOOS != "windows" || IsCurrent(s.Owner)) })
			if err != nil {
				t.Fatal(err)
			}
			socket := &quicProbeSocket{PacketConn: raw, scope: scope, writer: writer, destination: listener.Addr()}
			transport := &quic.Transport{Conn: socket}
			defer transport.Close()
			conn, err := transport.Dial(ctx, listener.Addr(), clientTLS, config)
			if badCertificate {
				if err == nil {
					conn.CloseWithError(0, "fixture done")
					t.Fatal("certificate verification bypassed")
				}
				if !writer.Evidence().Committed || accepted.Load() != 0 {
					t.Fatal("transform witness incorrectly treated as TLS proof", writer.Evidence())
				}
				cancel()
				listener.Close()
				<-served
				t.Log("committed_packet_plan=true authenticated_exchange=false wrong_certificate_rejected=true")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "fixture done")
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			body := bytes.Repeat([]byte("unchanged application body; "), 4096)
			if _, err = stream.Write(body); err != nil {
				t.Fatal(err)
			}
			if err = stream.Close(); err != nil {
				t.Fatal(err)
			}
			digest, err := io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			want := sha256.Sum256(body)
			if !bytes.Equal(digest, want[:]) {
				t.Fatal("QUIC stream body changed")
			}
			if err = <-served; err != nil {
				t.Fatal(err)
			}
			e := writer.Evidence()
			if !e.Committed || e.Failed || e.FakePackets != 6 || e.OriginalPackets != socket.unchanged.Load() || e.OriginalPackets < 2 || accepted.Load() != 1 {
				t.Fatal("send/cutoff/authenticated evidence", e, accepted.Load())
			}
			t.Logf("native_windows_owner=%t fake_packets=%d original_packets=%d exact_application_bytes=%d verified_mtls=true accepted_connections=1", runtime.GOOS == "windows", e.FakePackets, e.OriginalPackets, len(body))
		})
	}
}

func TestQUICProbeOwnerProcess(t *testing.T) {
	if os.Getenv("VELIQ_QUIC_PROBE_OWNER_CHILD") != "1" {
		t.Skip("isolated owner subprocess")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}
func quicProbeOwner(t *testing.T) ProcessIdentity {
	t.Helper()
	if runtime.GOOS != "windows" {
		return quicProbeScopeFixture().Owner
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "chrome.exe")
	if err = os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=^TestQUICProbeOwnerProcess$")
	cmd.Env = append(os.Environ(), "VELIQ_QUIC_PROBE_OWNER_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		stdin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	id, err := NewDiscovery().Lookup(uint32(cmd.Process.Pid))
	if err != nil || !IsCurrent(id) {
		t.Fatal("Windows owner identity", err)
	}
	return id
}
