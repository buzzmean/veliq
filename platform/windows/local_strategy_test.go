package windowsplatform

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/routing"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func localTestPacket() []byte {
	p := make([]byte, 80)
	p[0] = 0x45
	p[8] = 64
	p[9] = 6
	p[32] = 0x50
	p[33] = 0x18
	binary.BigEndian.PutUint16(p[2:], 80)
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{203, 0, 113, 9})
	binary.BigEndian.PutUint16(p[20:], 1234)
	binary.BigEndian.PutUint16(p[22:], 443)
	copy(p[40:], bytes.Repeat([]byte{7}, 40))
	return p
}
func TestLocalSimultaneousClassificationAndSend(t *testing.T) {
	e := localstrategy.New()
	e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "split", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.9"}, Strategy: "tcp-split-1", Cutoff: 1, Enabled: true}}})
	ledger := NewEvidenceLedger()
	tuple := Tuple{"tcp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.9:443")}
	classify := func(id ProcessIdentity, _ Tuple) Decision {
		if id.PID == 1 {
			return Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: e}
		}
		if id.PID == 3 {
			return Decision{Route: routing.Route{RelayID: "VPS-01"}}
		}
		return Decision{}
	}
	for _, id := range []ProcessIdentity{{PID: 1, CreationTime: 10, Path: "chosen.exe"}, {PID: 2, CreationTime: 20, Path: "control.exe"}, {PID: 3, CreationTime: 30, Path: "relay.exe"}, {PID: 4, CreationTime: 40, Path: "service.exe"}} {
		d, self := ClassifyCapture(id, tuple, 4, classify)
		if id.PID == 3 {
			if d.Route.RelayID != "VPS-01" {
				t.Fatal(d)
			}
			continue
		}
		sent := 0
		state := &localstrategy.State{}
		if err := SendLocal(d, state, id, tuple, localTestPacket(), func([]byte) error { sent++; return nil }, ledger); err != nil {
			t.Fatal(err)
		}
		if id.PID == 1 && sent != 2 || id.PID != 1 && sent != 1 || id.PID == 4 && !self {
			t.Fatalf("PID association/send %d %d", id.PID, sent)
		}
	}
	if ledger.Snapshot(1).Flows[0].Route != "DIRECT_PLUS" || ledger.Snapshot(2).Flows[0].Route != "DIRECT" {
		t.Fatal("evidence")
	}
}
func TestLocalReinjectionFailureAndUnknownIdentityFailOpen(t *testing.T) {
	e := localstrategy.New()
	e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "split", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.9"}, Strategy: "tcp-split-1", Cutoff: 1, Enabled: true}}})
	tuple := Tuple{"tcp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.9:443")}
	id := ProcessIdentity{PID: 1, CreationTime: 10, Path: "chosen.exe"}
	raw := localTestPacket()
	d := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: e}
	n := 0
	ledger := NewEvidenceLedger()
	st := &localstrategy.State{}
	err := SendLocal(d, st, id, tuple, raw, func(p []byte) error {
		n++
		if n == 2 {
			return errors.New("send failure")
		}
		if n == 3 && !bytes.Equal(p, raw) {
			t.Fatal("not original failopen")
		}
		return nil
	}, ledger)
	if err != nil || n != 3 || st.Applied() {
		t.Fatal(err, n, st)
	}
	if err := SendLocal(d, st, id, tuple, raw, func([]byte) error { return nil }, ledger); err != nil {
		t.Fatal(err)
	}
	if e.Metrics().Bytes != 0 {
		t.Fatal("disabled strategy counted unmodified DIRECT traffic as DIRECT+", e.Metrics())
	}
	if ledger.Snapshot(1).Flows[0].Route != "DIRECT" {
		t.Fatal("false local success")
	}
	n = 0
	SendLocal(d, &localstrategy.State{}, ProcessIdentity{PID: 1}, tuple, raw, func([]byte) error { n++; return nil }, ledger)
	if n != 1 {
		t.Fatal("unknown identity modified")
	}
	// A missing state is a fail-open engine error, not a panic or a transform.
	n = 0
	nilLedger := NewEvidenceLedger()
	if err := SendLocal(d, nil, id, tuple, raw, func([]byte) error { n++; return nil }, nilLedger); err != nil {
		t.Fatal(err)
	}
	f := nilLedger.Snapshot(id.PID).Flows[0]
	if n != 1 || f.Route != "DIRECT" || f.Counters.DirectPlus != 0 || f.Counters.DirectPlusBytes != 0 {
		t.Fatal("missing state did not fail open", n, f)
	}
}

func TestFragmentAddressHasCompletePrecomputedUDPChecksum(t *testing.T) {
	var address [80]byte
	address[10] = 2
	p := make([]byte, 44)
	p[0] = 0x45
	p[9] = 17
	p[6] = 0x20
	got := LocalPacketAddress(p, address)
	if got[10] != 0xa2 {
		t.Fatal(got[10])
	}
	p[6] = 0x40
	if got = LocalPacketAddress(p, address); got != address {
		t.Fatal("unfragmented address changed")
	}
}

// Empty ACKs before cutoff used to erase DIRECT_PLUS; after cutoff unchanged
// packets used to inflate modification counters. Exercise both with real splits.
func TestLocalTCPEvidenceSurvivesPassThrough(t *testing.T) {
	for _, cutoff := range []uint32{1, 2} {
		t.Run(fmt.Sprint(cutoff), func(t *testing.T) {
			e := localstrategy.New()
			if err := e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "split", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, Domains: []string{"example.org"}, Strategy: "tcp-split-1", Cutoff: cutoff, Enabled: true}}}); err != nil {
				t.Fatal(err)
			}
			ledger := NewEvidenceLedger()
			id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chosen.exe"}
			tuple := Tuple{"tcp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.9:443")}
			d := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: e}
			st := &localstrategy.State{}
			payload := []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
			packets := [][]byte{localTCPPacket(2, nil), localTCPPacket(16, nil), localTCPPacket(24, payload), localTCPPacket(16, nil), localTCPPacket(17, nil)}
			var total uint64
			for i, p := range packets {
				total += uint64(len(p))
				ledger.RecordBytes(id, tuple, "captured", "", uint64(len(p)))
				sent := 0
				if err := SendLocal(d, st, id, tuple, p, func([]byte) error { sent++; return nil }, ledger); err != nil {
					t.Fatal(err)
				}
				wantSent := 1
				if i == 2 {
					wantSent = 2
				}
				if sent != wantSent {
					t.Fatalf("packet %d: sent %d, want %d", i, sent, wantSent)
				}
				f := ledger.Snapshot(42).Flows[0]
				if i < 2 {
					if f.Route != "DIRECT" || f.Counters.DirectPlus != 0 {
						t.Fatalf("premature DIRECT+: %+v", f)
					}
				} else if f.Route != "DIRECT_PLUS" || f.Strategy != "split" || f.Domain != "example.org" || f.Counters.DirectPlus != 1 || f.Counters.DirectPlusBytes != uint64(len(packets[2])) || f.Counters.Relayed != 0 || f.RelayID != "" {
					t.Fatalf("packet %d: %+v", i, f)
				}
			}
			f := ledger.Snapshot(42).Flows[0]
			if f.Counters.Direct != 4 || f.Counters.DirectBytes+f.Counters.DirectPlusBytes != total {
				t.Fatalf("pass-through counters: %+v", f.Counters)
			}
			if e.Metrics().Bytes != uint64(len(packets[2])+len(packets[3])+len(packets[4])) {
				t.Fatal("flow-byte metric excludes ACK/FIN", e.Metrics())
			}
			if cutoff == 1 {
				// Even a payload packet is unchanged once the cutoff is reached.
				sent := 0
				if err := SendLocal(d, st, id, tuple, packets[2], func([]byte) error { sent++; return nil }, ledger); err != nil {
					t.Fatal(err)
				}
				f = ledger.Snapshot(42).Flows[0]
				if sent != 1 || f.Route != "DIRECT_PLUS" || f.Counters.DirectPlus != 1 || f.Counters.DirectPlusBytes != uint64(len(packets[2])) || f.Counters.Direct != 5 {
					t.Fatalf("cutoff inflated modifications: %+v", f)
				}
			}
			// A later policy disable must preserve proof of earlier real use,
			// but it must not count this new native packet as modified.
			d.Local = nil
			if err := SendLocal(d, st, id, tuple, packets[3], func([]byte) error { return nil }, ledger); err != nil {
				t.Fatal(err)
			}
			if f = ledger.Snapshot(42).Flows[0]; f.Route != "DIRECT_PLUS" || f.Counters.DirectPlus != 1 || f.Strategy != "split" || f.Domain != "example.org" {
				t.Fatalf("lost historical proof: %+v", f)
			}
			// Windows can reuse a tuple in the same process. Never inherit proof.
			ledger.BeginFlow(id, tuple)
			if err := SendLocal(d, &localstrategy.State{}, id, tuple, packets[0], func([]byte) error { return nil }, ledger); err != nil {
				t.Fatal(err)
			}
			if f = ledger.Snapshot(42).Flows[0]; f.Route != "DIRECT" || f.Counters.DirectPlus != 0 || f.Strategy != "" || f.Domain != "" {
				t.Fatalf("stale connection proof: %+v", f)
			}
			if ledger.Snapshot(42).Counters.DirectPlus != 1 {
				t.Fatal("connection reset erased lifetime totals")
			}
		})
	}
}

func localTCPPacket(flags byte, payload []byte) []byte {
	p := append(localTestPacket()[:40:40], payload...)
	p[33] = flags
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	return p
}

func TestLocalTCPConcurrentConnections(t *testing.T) {
	e := localstrategy.New()
	if err := e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "split", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.9"}, Strategy: "tcp-split-1", Cutoff: 2, Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	ledger := NewEvidenceLedger()
	start := make(chan struct{})
	var wg sync.WaitGroup
	// Same PID, distinct connections; every fourth connection fails open before
	// its first complete transform. Successful neighbours cannot lend it proof.
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chosen.exe"}
			tuple := Tuple{"tcp", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(2000+n)), netip.MustParseAddrPort("203.0.113.9:443")}
			st := &localstrategy.State{}
			d := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: e}
			packets := [][]byte{localTCPPacket(2, nil), localTCPPacket(16, nil), localTestPacket(), localTCPPacket(16, nil), localTCPPacket(17, nil)}
			for i, p := range packets {
				binary.BigEndian.PutUint16(p[20:], tuple.Source.Port())
				sends := 0
				if err := SendLocal(d, st, id, tuple, p, func([]byte) error {
					sends++
					if n%4 == 0 && i == 2 && sends == 2 {
						return errors.New("injected split send failure")
					}
					return nil
				}, ledger); err != nil {
					t.Error(err)
				}
				// Also exercise concurrent snapshots during atomic publication.
				for _, f := range ledger.Snapshot(42).Flows {
					if f.Counters.DirectPlus > 0 && (f.Route != "DIRECT_PLUS" || f.Strategy != "split") {
						t.Errorf("inconsistent publication: %+v", f)
					}
				}
			}
		}(n)
	}
	close(start)
	wg.Wait()
	s := ledger.Snapshot(42)
	if len(s.Flows) != 16 {
		t.Fatal("missing independent connections", len(s.Flows))
	}
	for _, f := range s.Flows {
		port := netip.MustParseAddrPort(f.Source).Port()
		if (port-2000)%4 == 0 {
			if f.Route != "DIRECT" || f.Counters.DirectPlus != 0 || f.Counters.DirectPlusBytes != 0 || f.Strategy != "" {
				t.Errorf("failed connection falsely transformed: %+v", f)
			}
		} else if f.Route != "DIRECT_PLUS" || f.Counters.DirectPlus != 1 || f.Counters.DirectPlusBytes != 80 || f.Counters.Direct != 4 {
			t.Errorf("successful connection lost proof: %+v", f)
		}
		if f.Counters.Relayed != 0 || f.Counters.RelayedBytes != 0 || f.RelayID != "" {
			t.Errorf("relay evidence leak: %+v", f)
		}
	}
}

func localTestHello(t *testing.T) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer b.Close()
	go func() {
		defer a.Close()
		_ = tls.Client(a, &tls.Config{ServerName: "www.youtube.com", CurvePreferences: []tls.CurveID{tls.X25519}}).Handshake()
	}()
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1400)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf[:n]...)
}
func TestLocalChainFullSendEvidenceAndFailure(t *testing.T) {
	e := localstrategy.New()
	if err := e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "chain", Name: "test", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.9"}, Strategy: "chain", Actions: []localstrategy.Action{{Kind: "fake-tls", TTL: 5}, {Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1, 5}}, {Kind: "tcp-disorder"}}, Preset: "youtube", PresetVersion: 2, Cutoff: 1, Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chosen.exe"}
	tuple := Tuple{"tcp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.9:443")}
	d := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: e, LocalStrategyID: "chain"}
	payload := localTestHello(t)
	for _, fail := range []bool{false, true} {
		ledger := NewEvidenceLedger()
		st := &localstrategy.State{}
		syn := localTCPPacket(2, nil)
		binary.BigEndian.PutUint32(syn[24:], 99)
		if err := SendLocal(d, st, id, tuple, syn, func([]byte) error { return nil }, ledger); err != nil {
			t.Fatal(err)
		}
		st.ConfirmHandshake(100, 199)
		raw := localTCPPacket(24, payload)
		binary.BigEndian.PutUint32(raw[24:], 100)
		binary.BigEndian.PutUint32(raw[28:], 200)
		count := 0
		err := SendLocal(d, st, id, tuple, raw, func([]byte) error {
			count++
			if fail && count == 2 {
				return errors.New("injected send failure")
			}
			return nil
		}, ledger)
		if err != nil {
			t.Fatal(err)
		}
		f := ledger.Snapshot(42).Flows[0]
		if fail {
			if f.Route != "DIRECT" || f.Counters.DirectPlus != 0 || f.Counters.FakeTLS != 0 {
				t.Fatal("partial plan falsely committed", f)
			}
			if f.LocalInspection == nil || !f.LocalInspection.SendFailed || f.LocalInspection.OutputPacketsSent != 1 || f.LocalInspection.Reason != "TRANSFORM_SEND_FAILED" {
				t.Fatal("partial output diagnosis missing", f.LocalInspection)
			}
			continue
		}
		if count != 4 || f.Route != "DIRECT_PLUS" || f.Counters.FakeTLS != 1 || f.FakeTTL != 5 || f.Preset != "youtube" || f.Counters.Relayed != 0 || f.Counters.DirectPlus != 1 {
			t.Fatal(f, count)
		}
		if err := SendLocal(d, st, id, tuple, localTCPPacket(16, nil), func([]byte) error { return nil }, ledger); err != nil {
			t.Fatal(err)
		}
		if f = ledger.Snapshot(42).Flows[0]; f.Route != "DIRECT_PLUS" || f.Counters.FakeTLS != 1 || f.Counters.DirectPlus != 1 {
			t.Fatal("ACK lost real plan evidence", f)
		}
	}
}

func TestPassiveInspectionSurvivesACKWithoutChangingRoute(t *testing.T) {
	e := localstrategy.New()
	if err := e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "sni", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, Domains: []string{"www.youtube.com"}, Strategy: "chain", Actions: []localstrategy.Action{{Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1}}}, Cutoff: 1, Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	ledger := NewEvidenceLedger()
	st := &localstrategy.State{}
	id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chosen.exe"}
	tuple := Tuple{"tcp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.9:443")}
	d := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: e, LocalStrategyID: "sni"}
	hello := localTestHello(t)
	for _, p := range [][]byte{localTCPPacket(24, hello[:30]), localTCPPacket(16, nil), localTCPPacket(17, nil)} {
		if err := SendLocal(d, st, id, tuple, p, func([]byte) error { return nil }, ledger); err != nil {
			t.Fatal(err)
		}
	}
	f := ledger.Snapshot(42).Flows[0]
	if f.LocalInspection == nil || f.LocalInspection.Reason != "CLIENTHELLO_INCOMPLETE" || f.Route != "DIRECT" || f.Counters.DirectPlus != 0 || f.Counters.Relayed != 0 || f.Counters.Direct != 3 {
		t.Fatalf("passive diagnostic changed routing/counters: %+v", f)
	}
	f.LocalInspection.Reason = "external snapshot mutation"
	if ledger.Snapshot(42).Flows[0].LocalInspection.Reason != "CLIENTHELLO_INCOMPLETE" {
		t.Fatal("snapshot retained mutable ledger pointer")
	}
	ledger.BeginFlow(id, tuple)
	if len(ledger.Snapshot(42).Flows) != 0 {
		t.Fatal("reused tuple retained old inspection")
	}
}
