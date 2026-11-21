//go:build windows

package windowsplatform

import (
	"context"
	"fmt"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBrowserAliasCleanupBeforeFirstCapturedSYN(t *testing.T) {
	ledger := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 17, Path: `C:\Apps\chrome.exe`}
	redirect := &tcpRedirect{b: &WinDivertBackend{evidence: ledger}, state: newTCPState(16), delegated: map[Tuple]delegatedTCP{}}
	dest := netip.MustParseAddrPort("203.0.113.1:443")
	for i := uint16(0); i < 3; i++ {
		original := Tuple{Protocol: "tcp", Source: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 1200+i), Destination: dest}
		upstream := original
		upstream.Source = netip.AddrPortFrom(original.Source.Addr(), 2200+i)
		ledger.BeginFlow(id, original)
		ledger.RecordBytes(id, original, "captured", "", 40)
		if !ledger.BindUpstream(id, upstream, original) {
			t.Fatal("bind")
		}
		if i < 2 {
			redirect.delegated[upstream] = delegatedTCP{}
		}
	}
	// Exactly the cleanup race: reservation exists, SYN has not arrived in state.
	redirect.state.mu.Lock()
	redirect.pruneEvidenceAliases()
	redirect.state.mu.Unlock()
	if len(ledger.aliases) != 2 {
		t.Fatal("lost live pre-SYN reservation or retained dead alias", len(ledger.aliases))
	}
	for i := uint16(0); i < 2; i++ {
		original := Tuple{Protocol: "tcp", Source: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 1200+i), Destination: dest}
		upstream := original
		upstream.Source = netip.AddrPortFrom(original.Source.Addr(), 2200+i)
		ledger.BeginFlow(id, upstream)
		ledger.RecordLocal(id, upstream, "disorder", "www.youtube.com", 100+uint64(i))
		proof, err := ledger.SnapshotQuery(EvidenceQuery{Source: original.Source.String()}, nil)
		if err != nil || len(proof.Flows) != 1 || proof.Flows[0].Counters.DirectPlusBytes != 100+uint64(i) || proof.Flows[0].Counters.RelayedBytes != 0 {
			t.Fatal("transform not attributed to exact CONNECT", err, proof)
		}
		redirect.releaseDelegated(upstream, id)
	}
	if len(ledger.aliases) != 0 {
		t.Fatal("released aliases retained")
	}
}

func TestNativeDelegatedLoopbackReplyUsesExactReflection(t *testing.T) {
	b, _ := captureFixture(t)
	b.testBrowserLoopback = true
	redirect := &tcpRedirect{b: b, port: 19000, state: newTCPState(16), delegated: map[Tuple]delegatedTCP{}}
	tuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("127.0.0.1:12000"), Destination: netip.MustParseAddrPort("127.0.0.1:443")}
	entry := redirect.state.add(tuple, ProcessIdentity{PID: 42}, Decision{Deferred: true}, "opening", time.Now())
	entry.mode = "relay"
	reply := Tuple{Protocol: "tcp", Source: netip.AddrPortFrom(tuple.Source.Addr(), redirect.port), Destination: netip.AddrPortFrom(tuple.Destination.Addr(), entry.virtual)}
	var written Tuple
	b.packetWriter = func(p []byte, _ [80]byte) error { written, _, _, _ = ParseTCP(p); return nil }
	packet := tcpPacket(t, reply)
	packet[33] = 0x12
	var addr [80]byte
	addr[10] = 6
	redirect.processPacket(packet, addr, func(ProcessIdentity, Tuple) Decision { t.Fatal("classified exact listener reply"); return Decision{} })
	if written.Source != tuple.Destination || written.Destination != tuple.Source {
		t.Fatal("listener reply bypassed native reflection", written)
	}
	// A different local port/address must still be passed unchanged.
	other := reply
	other.Destination = netip.MustParseAddrPort("127.0.0.1:15000")
	redirect.processPacket(tcpPacket(t, other), addr, func(ProcessIdentity, Tuple) Decision { t.Fatal("captured unrelated loopback"); return Decision{} })
	if written != other {
		t.Fatal("unrelated loopback intercepted", written)
	}
}

func TestNativeDelegationTestDestinationNeverChangesProduction(t *testing.T) {
	dest := netip.MustParseAddrPort("127.0.0.1:443")
	b := &WinDivertBackend{}
	if b.nativeDelegationDestination(dest) != dest {
		t.Fatal("production destination changed")
	}
	b.testBrowserLoopback = true
	if b.nativeDelegationDestination(dest).Addr() != netip.MustParseAddr("192.0.2.254") {
		t.Fatal("fixture still attempts loopback NAT")
	}
	public := netip.MustParseAddrPort("203.0.113.9:443")
	if b.nativeDelegationDestination(public) != public {
		t.Fatal("fixture changed a real origin")
	}
}

func TestNativePlannedOpenAcknowledgesOnlyRealUpstreamAndNeverSendsOriginalSYN(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			b, _ := captureFixture(t)
			redirect := &tcpRedirect{b: b, port: 19000, state: newTCPState(16), delegated: map[Tuple]delegatedTCP{}}
			tuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:12000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
			up, peer := net.Pipe()
			defer up.Close()
			defer peer.Close()
			opened := 0
			sent := 0
			d := Decision{NewConnectionsOnly: true, BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.Direct}}
			d.OpenDeferred = func(ctx context.Context, d Decision, reason string) (net.Conn, Decision, error) {
				opened++
				if reason != "CONNECT_AUTHORITY" {
					t.Fatal(reason)
				}
				if fail {
					return nil, d, context.DeadlineExceeded
				}
				return up, d, nil
			}
			entry := redirect.state.add(tuple, ProcessIdentity{PID: 42}, d, "opening", time.Now())
			b.packetWriter = func(packet []byte, _ [80]byte) error {
				sent++
				got, _, _, err := ParseTCP(packet)
				if err != nil || got.Destination.Port() != redirect.port {
					t.Fatal("original SYN leaked", got, err)
				}
				return nil
			}
			redirect.wg.Add(1)
			redirect.open(entry, tcpPacket(t, tuple), [80]byte{}, func() {})
			if opened != 1 {
				t.Fatal("callback skipped")
			}
			if fail {
				if entry.mode != "block" || sent != 0 || entry.upstream != nil {
					t.Fatal("failed OPEN acknowledged or fell DIRECT", entry.mode, sent)
				}
			} else {
				if entry.mode != "relay" || sent != 1 || entry.upstream == nil || !entry.decision.Route.Direct() {
					t.Fatal("successful DIRECT upstream was treated as fallback", entry.mode, sent)
				}
			}
		})
	}
}

func TestNativeFailedHandoffRetiresOnlyItsUnacceptedUpstream(t *testing.T) {
	for _, kind := range []string{"opening", "relay", "accepted", "foreign", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			b, _ := captureFixture(t)
			r := &tcpRedirect{b: b, state: newTCPState(16)}
			id := ProcessIdentity{PID: 42, CreationTime: 17, Path: `C:\Apps\chrome.exe`}
			tuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
			d := Decision{OpenDeferred: func(context.Context, Decision, string) (net.Conn, Decision, error) { return nil, Decision{}, nil }}
			e := r.state.add(tuple, id, d, "opening", time.Now())
			up, peer := net.Pipe()
			defer up.Close()
			defer peer.Close()
			e.upstream = up
			if kind != "opening" {
				e.mode = "relay"
			}
			if kind == "accepted" {
				local, other := net.Pipe()
				defer local.Close()
				defer other.Close()
				e.local = local
			}
			if kind == "foreign" {
				id.CreationTime++
			}
			if kind == "legacy" {
				e.decision.OpenDeferred = nil
			}
			r.abortUnacceptedDelegated(tuple, id)
			shouldClose := kind == "opening" || kind == "relay"
			if (e.mode == "closed") != shouldClose || (e.upstream == nil) != shouldClose {
				t.Fatal("incorrect handoff cleanup", kind, e.mode)
			}
			if shouldClose {
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				var one [1]byte
				if _, err := peer.Read(one[:]); err != io.EOF {
					t.Fatal("orphan upstream not closed", err)
				}
			}
		})
	}
}
