package localstrategy

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestBrowserYouTubeRepeatedFakesKeepFivePacketBoundAndOldSequence(t *testing.T) {
	for _, candidate := range BrowserYouTubeCandidates() {
		p := chainProfile(candidate.Actions...)
		e := engine(t, p)
		st := confirmed(e, 1000)
		raw := tlsInput(1000)
		r := e.Process(raw, st, metadata())
		if len(r.Packets) > 5 {
			t.Fatal(candidate.ID, "unbounded", len(r.Packets))
		}
		if candidate.ID == "fake5x2-disorder" || candidate.ID == "fake8x2-disorder" {
			if r.FakePackets != 2 || len(r.Packets) != 5 {
				t.Fatal(candidate.ID, r)
			}
			for _, packet := range r.Packets[:2] {
				checkPacket(t, packet)
				payload, _ := packetPayload(packet, "tcp")
				if int32(binary.BigEndian.Uint32(packet[24:])-1000)+int32(len(payload)) != 0 {
					t.Fatal("fake overlaps real sequence")
				}
			}
		}
		next := e.Process(raw, st, metadata())
		if next.Modified || next.FakePackets != 0 {
			t.Fatal("cutoff ignored", candidate.ID)
		}
	}
	p := chainProfile(Action{Kind: "fake-tls", TTL: 5, Repeats: 2}, Action{Kind: "tcp-multisplit", Positions: []uint16{1, 2, 3}})
	if validateChain(p) == nil {
		t.Fatal("six packets accepted")
	}
	p.Actions[0].Repeats = 3
	if validateChain(p) == nil {
		t.Fatal("repeat bound ignored")
	}
}

func TestBrowserYouTubeRepeatedFakesOnActualSegmentedHelloPlan(t *testing.T) {
	for _, candidate := range BrowserYouTubeCandidates()[:2] {
		p := assemblyProfile(candidate.Actions)
		e := engine(t, p)
		base := uint32(5000)
		st := confirmed(e, base)
		var buffer HelloBuffer
		data := largeHello(1955)
		inputs := parts(data, 2, base)
		var result *BufferedResult
		for _, packet := range inputs {
			accepted, out := e.BufferTCP(packet, st, &buffer, metadata(), time.Now())
			if !accepted {
				t.Fatal("not buffered")
			}
			result = out
		}
		if result == nil || !result.Result.Modified || result.Result.FakePackets != 2 {
			t.Fatal("segmented path omitted repeats", result)
		}
		if len(result.Result.Packets) > 5*len(inputs) {
			t.Fatal("output bound")
		}
		assertStream(t, result.Result, data, base)
	}
}
