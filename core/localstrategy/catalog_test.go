package localstrategy

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestCatalogInventoryAllGeneralAndUnsupportedAreExplicit(t *testing.T) {
	c := BundledCatalog()
	if len(c.Files) != 22 || c.Release != "1.10.4" || len(c.Sources) != 4 {
		t.Fatal("incomplete release inventory")
	}
	plans, caps := c.Compile()
	if len(plans) < 4 || len(plans) > 48 || len(caps) != len(c.Rules) {
		t.Fatal("catalog compile inventory", len(plans), len(caps))
	}
	unsupported := 0
	highRepeats := false
	for _, cap := range caps {
		if !cap.Supported {
			unsupported++
			if cap.Reason == "" || cap.Plan != "" {
				t.Fatal("unsupported mode silently executable")
			}
		}
	}
	for _, plan := range plans {
		for _, a := range plan.Actions {
			highRepeats = highRepeats || a.Repeats >= 11 || a.Native != nil && a.Native.Repeats >= 11
		}
	}
	if unsupported == 0 || !highRepeats {
		t.Fatal("unsupported/Flowseal repeats evidence absent")
	}
	t.Logf("%d general files, %d rules, %d own executable plans, %d explicitly unsupported", len(c.Files), len(c.Rules), len(plans), unsupported)
}
func catalogTestEngine(t *testing.T, actions []Action) (*LocalStrategyEngine, Metadata, *State) {
	t.Helper()
	p := chainProfile(actions...)
	p.Preset = "browser-catalog"
	p.Application = "chrome.exe"
	e := engine(t, p)
	m := metadata()
	m.Application = `C:\Chrome\chrome.exe`
	st := &State{}
	syn := packet(6, nil)
	syn[33] = 2
	binary.BigEndian.PutUint32(syn[24:], 999)
	checksumTransport(syn)
	e.Process(syn, st, m)
	st.ConfirmHandshake(1000, 99)
	return e, m, st
}
func TestLegacyCatalogPacketsPreserveTLSAndCannotEnterSequenceSpace(t *testing.T) {
	plans, _ := BundledCatalog().Compile()
	for _, plan := range plans {
		t.Run(plan.ID, func(t *testing.T) {
			e, m, st := catalogTestEngine(t, plan.Actions)
			if len(plan.Actions) == 1 && plan.Actions[0].Native != nil {
				return
			} // Native recipes have separate PAWS/MD5/sequence shape tests below.
			data := largeHello(1955)
			inputs := parts(data, 2, 1000)
			var buf HelloBuffer
			var out *BufferedResult
			for _, p := range inputs {
				_, out = e.BufferTCP(p, st, &buf, m, time.Now())
			}
			if out == nil || !out.Result.Modified {
				t.Fatal("catalog did not transform")
			}
			r := out.Result
			if len(r.Packets) > 20*len(inputs) || r.FakePackets > 16 {
				t.Fatal("catalog bound exceeded")
			}
			for i, q := range r.Packets {
				checkPacket(t, q)
				if len(q) > 1500 {
					t.Fatal("MTU exceeded")
				}
				if uint64(i) < r.FakePackets {
					header := 20 + int(q[32]>>4)*4
					size := len(q) - header
					if int32(binary.BigEndian.Uint32(q[24:])-1000)+int32(size) >= 0 {
						t.Fatal("fake overlaps application sequence")
					}
				}
			}
			assertCatalogReceiver(t, r, data, 1000, plan.Actions)
			if again := e.Process(inputs[0], st, m); again.Modified {
				t.Fatal("cutoff did not stop")
			}
		})
	}
}
func TestCatalogScopeBudgetAutottlAndOwnTemplate(t *testing.T) {
	for _, fooling := range []string{"badseq", "ts", "md5sig", "ts,md5sig"} {
		actions := []Action{{Kind: "fake-tls", TTL: 16, Repeats: 11, FakeModel: "tls13-google", Fooling: fooling, AutoTTL: true}, {Kind: "tcp-multisplit", Markers: []string{"1", "midsld"}}, {Kind: "tcp-disorder"}}
		e, m, st := catalogTestEngine(t, actions)
		st.ObserveServerTTL(56)
		r := e.Process(tlsInput(1000), st, m)
		if r.FakePackets != 11 || r.FakeTTL != 7 || len(r.Packets) != 14 {
			t.Fatal("missing own plan", fooling, r.FakePackets, r.FakeTTL, len(r.Packets))
		}
		for _, q := range r.Packets {
			checkPacket(t, q)
		}
		p := chainProfile(actions...)
		if validateChain(p) == nil {
			t.Fatal("legacy five-packet ceiling weakened")
		}
		p.Preset = "browser-catalog"
		p.Application = "TslGame.exe"
		if validateChain(p) == nil {
			t.Fatal("catalog escaped browser scope")
		}
		p.Application = "chrome.exe"
		p.Cutoff = 2
		if validateChain(p) == nil {
			t.Fatal("catalog cutoff escaped")
		}
	}
	h := ownCatalogHello("www.google.com")
	h2 := ownCatalogHello("www.google.com")
	if len(h) != 1250 || string(h) == string(h2) {
		t.Fatal("own fake size/randomness")
	}
	start, size, ok := tlsSNI(h)
	if !ok || string(h[start:start+size]) != "www.google.com" {
		t.Fatal("invalid own fake framing")
	}
}

// Model the TCP receiver's duplicate-prefix trim explicitly. Standalone fakes
// must STILL be wholly old; only a declared seqovl real fragment may cross RCV.NXT.
func assertCatalogReceiver(t *testing.T, r Result, original []byte, base uint32, actions []Action) {
	t.Helper()
	got := make([]byte, len(original))
	seen := make([]bool, len(original))
	overlap := 0
	for _, a := range actions {
		if a.SequenceOverlap != 0 {
			overlap = int(a.SequenceOverlap)
		}
	}
	observed := 0
	for i, q := range r.Packets {
		header := 20 + int(q[32]>>4)*4
		payload := q[header:]
		offset := int(int32(binary.BigEndian.Uint32(q[24:]) - base))
		if uint64(i) < r.FakePackets {
			if offset >= 0 || offset+len(payload) >= 0 {
				t.Fatal("standalone fake may enter application stream")
			}
			continue
		}
		if offset < 0 {
			if overlap == 0 || offset != -overlap || len(payload) <= overlap {
				t.Fatal("undeclared or incomplete sequence overlap")
			}
			if _, _, ok := tlsSNI(payload[:overlap]); !ok {
				t.Fatal("overlap prefix not a complete own fake")
			}
			payload = payload[overlap:]
			offset = 0
			observed++
		}
		if offset < 0 || offset+len(payload) > len(original) {
			t.Fatal("real output outside application stream")
		}
		for j, v := range payload {
			if seen[offset+j] && got[offset+j] != v {
				t.Fatal("conflicting real bytes")
			}
			seen[offset+j] = true
			got[offset+j] = v
		}
	}
	if overlap != 0 && observed != 1 {
		t.Fatal("missing bounded first-fragment overlap")
	}
	for _, v := range seen {
		if !v {
			t.Fatal("application stream hole")
		}
	}
	if !bytes.Equal(got, original) {
		t.Fatal("application TLS bytes changed")
	}
}
