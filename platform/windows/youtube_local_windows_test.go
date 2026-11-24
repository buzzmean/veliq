//go:build windows

package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"unsafe"

	"github.com/buzzmean/veliq/core/localstrategy"
)

// Pinned native checksum helper only; no WinDivertOpen, driver, traffic or VPS.
func TestYouTubeRepeatedFakeChecksumsWithPinnedDLL(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	checksum, err := dll.FindProc("WinDivertHelperCalcChecksums")
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range localstrategy.BrowserYouTubeCandidates()[:2] {
		engine := localstrategy.New()
		if err = engine.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "browser-yt", Name: "fixture", Version: 1, Application: "chrome.exe", Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.9"}, Strategy: "chain", Actions: candidate.Actions, Cutoff: 1, Enabled: true}}}); err != nil {
			t.Fatal(err)
		}
		metadata := localstrategy.Metadata{Application: "chrome.exe", Protocol: "tcp", Destination: netip.MustParseAddrPort("203.0.113.9:443")}
		state := &localstrategy.State{}
		syn := localTCPPacket(2, nil)
		binary.BigEndian.PutUint32(syn[24:], 99)
		engine.Process(syn, state, metadata)
		state.ConfirmHandshake(100, 199)
		raw := localTCPPacket(24, localTestHello(t))
		binary.BigEndian.PutUint32(raw[24:], 100)
		binary.BigEndian.PutUint32(raw[28:], 200)
		result := engine.Process(raw, state, metadata)
		if result.FakePackets != 2 || len(result.Packets) != 5 {
			t.Fatal("bounded repeated plan absent", candidate.ID, result)
		}
		for _, packet := range result.Packets {
			before := append([]byte(nil), packet...)
			var address [80]byte
			checksum.Call(uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&address[0])), 0)
			if !bytes.Equal(before, packet) {
				t.Fatal("independent native checksum disagreement", candidate.ID)
			}
		}
	}
}

func TestCatalogFakeChecksumsWithPinnedDLL(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	checksum, err := dll.FindProc("WinDivertHelperCalcChecksums")
	if err != nil {
		t.Fatal(err)
	}
	plans, _ := localstrategy.BundledCatalog().Compile()
	for _, plan := range plans {
		engine := localstrategy.New()
		p := localstrategy.Profile{ID: "catalog-test", Name: "fixture", Version: 1, Preset: "browser-catalog", Application: "chrome.exe", Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.9"}, Strategy: "chain", Actions: plan.Actions, Cutoff: 1, Enabled: true}
		if err := engine.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{p}}); err != nil {
			t.Fatal(err)
		}
		metadata := localstrategy.Metadata{Application: "chrome.exe", StrategyID: "catalog-test", Protocol: "tcp", Destination: netip.MustParseAddrPort("203.0.113.9:443")}
		state := &localstrategy.State{}
		syn := localTCPPacket(2, nil)
		binary.BigEndian.PutUint32(syn[24:], 99)
		if plan.Actions[0].Native != nil && strings.Contains(plan.Actions[0].Native.Fooling, "ts") {
			syn = localTimestampFixturePacket(syn)
		}
		synResult := engine.Process(syn, state, metadata)
		for _, packet := range synResult.Packets {
			before := append([]byte(nil), packet...)
			var address [80]byte
			checksum.Call(uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&address[0])), 0)
			if !bytes.Equal(before, packet) {
				t.Fatal("SYN-data checksum mismatch")
			}
		}
		state.ConfirmHandshake(100, 199)
		state.ObserveServerTTL(56)
		raw := localTCPPacket(24, localTestHello(t))
		binary.BigEndian.PutUint32(raw[24:], 100)
		binary.BigEndian.PutUint32(raw[28:], 200)
		if plan.Actions[0].Native != nil && strings.Contains(plan.Actions[0].Native.Fooling, "ts") {
			raw = localTimestampFixturePacket(raw)
		}
		result := engine.Process(raw, state, metadata)
		if (!result.Modified && !(len(plan.Actions) == 1 && plan.Actions[0].Native != nil && strings.HasPrefix(plan.Actions[0].Native.Mode, "syndata"))) || len(result.Packets) > localstrategy.NativeTCPPacketLimit {
			t.Fatal("missing/unbounded catalog plan", plan.ID)
		}
		for _, packet := range result.Packets {
			before := append([]byte(nil), packet...)
			var address [80]byte
			checksum.Call(uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&address[0])), 0)
			if !bytes.Equal(before, packet) {
				t.Fatal("catalog checksum differs from pinned DLL", plan.ID)
			}
		}
	}
}

func localTimestampFixturePacket(p []byte) []byte {
	h := 20 + int(p[32]>>4)*4
	q := make([]byte, len(p)+12)
	copy(q, p[:h])
	copy(q[h:], []byte{1, 1, 8, 10, 0, 15, 66, 64, 0, 0, 0, 1})
	copy(q[h+12:], p[h:])
	q[32] += 3 << 4
	binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
	return q // engine recalculates every emitted packet; input is deliberately offload-style.
}
