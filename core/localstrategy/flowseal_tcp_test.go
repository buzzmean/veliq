package localstrategy

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func withNativeTimestamp(p []byte) []byte {
	h := 20 + int(p[32]>>4)*4
	q := make([]byte, len(p)+12)
	copy(q, p[:h])
	copy(q[h:], []byte{1, 1, 8, 10, 0, 15, 66, 64, 0, 0, 0, 1})
	copy(q[h+12:], p[h:])
	q[32] += 3 << 4
	binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
	checksumTransport(q)
	return q
}
func nativeFixture(t *testing.T, a []Action) (*LocalStrategyEngine, Metadata, *State, Result) {
	t.Helper()
	p := chainProfile(a...)
	p.Preset = "browser-catalog"
	p.Application = "chrome.exe"
	e := engine(t, p)
	m := metadata()
	m.Application = "chrome.exe"
	m.StrategyID = p.ID
	st := &State{}
	syn := packet(6, nil)
	syn[33] = 2
	binary.BigEndian.PutUint32(syn[24:], 999)
	checksumTransport(syn)
	syn = withNativeTimestamp(syn)
	r := e.Process(syn, st, m)
	st.ConfirmHandshake(1000, 99)
	return e, m, st, r
}
func TestEveryFlowsealTCP443RuleHasAnExecutedRecipe(t *testing.T) {
	count := 0
	for _, rule := range BundledCatalog().Rules {
		if rule.Source != "flowseal" {
			continue
		}
		tcp := false
		for _, a := range rule.Applies {
			tcp = tcp || a == "tcp443"
		}
		if !tcp {
			continue
		}
		count++
		t.Run(rule.ID, func(t *testing.T) {
			a, reason := rule.actions()
			if reason != "" || len(a) != 1 || a[0].Native == nil {
				t.Fatal("not an actual native recipe", reason)
			}
			plan := a[0].Native
			e, m, st, syn := nativeFixture(t, a)
			if strings.Contains(plan.Mode, "syndata") {
				if !syn.Modified || syn.FakePackets != uint64(plan.Repeats) {
					t.Fatal("SYN-data not sent")
				}
				for _, p := range syn.Packets {
					checkPacket(t, p)
					h := 20 + int(p[32]>>4)*4
					if len(p)-h != 16 || p[33]&0x3f != 2 || binary.BigEndian.Uint32(p[24:]) != 999 {
						t.Fatal("SYN-data recipe mismatch")
					}
				}
			}
			original := largeHello(1955)
			inputs := parts(original, 2, 1000)
			for i := range inputs {
				inputs[i] = withNativeTimestamp(inputs[i])
			}
			var b HelloBuffer
			var out *BufferedResult
			for _, p := range inputs {
				_, out = e.BufferTCP(p, st, &b, m, time.Now())
			}
			if out == nil {
				t.Fatal("no first-flight result")
			}
			r := out.Result
			pureSyn := plan.Mode == "syndata" || plan.Mode == "syndata,multidisorder" && len(plan.Markers) == 0
			if !r.Modified && !pureSyn {
				t.Fatal("mode listed but not executed", plan.Mode, r.Inspection)
			}
			if len(r.Packets) > NativeTCPPacketLimit {
				t.Fatal("unbounded output")
			}
			// Original segments must reconstruct byte-for-byte. This does not assume
			// that every origin rejects an in-window TS fake: that is probed live.
			got := make([]byte, len(original))
			seen := make([]bool, len(original))
			for i, q := range r.Packets {
				checkPacket(t, q)
				if len(q) > 1500 {
					t.Fatal("MTU")
				}
				if r.FakeAt(i) {
					continue
				}
				h := 20 + int(q[32]>>4)*4
				data := q[h:]
				offset := int(int32(binary.BigEndian.Uint32(q[24:]) - 1000))
				if offset < 0 {
					if plan.SequenceOverlap == 0 || -offset > len(data) {
						t.Fatal("undeclared overlap")
					}
					data = data[-offset:]
					offset = 0
				}
				if offset+len(data) > len(got) {
					t.Fatal("original sequence overflow")
				}
				copy(got[offset:], data)
				for j := range data {
					seen[offset+j] = true
				}
			}
			if pureSyn {
				return
			}
			if !bytes.Equal(got, original) {
				t.Fatal("real TLS bytes altered")
			}
			for _, v := range seen {
				if !v {
					t.Fatal("real TLS byte missing")
				}
			}
			if again := e.Process(inputs[0], st, m); again.Modified {
				t.Fatal("cutoff must bound first flight")
			}
		})
	}
	if count != 64 {
		t.Fatal("Flowseal inventory changed", count)
	}
}
func TestNativeFoolingIsNotSilentlyOldSequence(t *testing.T) {
	base := withNativeTimestamp(tlsInput(1000))
	ack := binary.BigEndian.Uint32(base[28:])
	for _, mode := range []string{"ts", "md5sig", "ts,md5sig", "badseq"} {
		p := &NativeTCPPlan{Fooling: mode, BadSequence: 2, BadACK: -66000, TimestampDelta: -600000}
		q := nativeTCPPacket(base, []byte{1, 2, 3}, 0, true, p)
		if q == nil {
			t.Fatal(mode)
		}
		checkPacket(t, q)
		seq := binary.BigEndian.Uint32(q[24:])
		if mode == "badseq" {
			if seq != 1002 || binary.BigEndian.Uint32(q[28:]) != ack+uint32(p.BadACK) {
				t.Fatal("badseq/ack increments ignored")
			}
		} else if seq != 1000 || binary.BigEndian.Uint32(q[28:]) != ack {
			t.Fatal("TS/MD5 unexpectedly forced into old sequence space")
		}
		if strings.Contains(mode, "ts") {
			if binary.BigEndian.Uint32(q[44:]) != 1000000+uint32(p.TimestampDelta) {
				t.Fatal("TS delta")
			}
		}
	}
}
func TestPureTSWithoutTimestampCannotInjectInWindowFake(t *testing.T) {
	a := []Action{{Kind: "native-tcp443", Native: &NativeTCPPlan{Mode: "fake", Repeats: 1, Fooling: "ts", Models: []NativeFakeModel{{Kind: "tls", Host: "www.google.com"}}}}}
	e, m, st, _ := nativeFixture(t, a)
	r := e.Process(tlsInput(1000), st, m)
	if r.Modified || r.Inspection == nil || r.Inspection.Reason != "TIMESTAMP_OPTION_REQUIRED" {
		t.Fatal("unsafe TS fake on non-TS TCP", r)
	}
}
func TestNativeTemplateRandomizationAndSID(t *testing.T) {
	m := NativeFakeModel{Kind: "tls", Host: "www.google.com"}
	a := nativeModel(m, nil)
	b := nativeModel(m, nil)
	if !bytes.Equal(a, b) {
		t.Fatal("none is not stable")
	}
	m.Randomize = true
	if bytes.Equal(nativeModel(m, nil), nativeModel(m, nil)) {
		t.Fatal("rnd ignored")
	}
	m.DuplicateSID = true
	hello := ownCatalogHello("test.example")
	got := nativeModel(m, hello)
	if !bytes.Equal(got[44:76], hello[44:76]) {
		t.Fatal("dupsid ignored")
	}
}

func TestNativeLargeOffloadFirstFlightIsSegmentedWithoutTLSRewrite(t *testing.T) {
	rule := CatalogRule{Options: map[string][]string{"dpi-desync": {"fake,multisplit"}, "dpi-desync-fooling": {"badseq"}, "dpi-desync-repeats": {"6"}, "dpi-desync-split-pos": {"1,midsld"}}}
	a, reason := compileNativeTCP(rule)
	if reason != "" {
		t.Fatal(reason)
	}
	e, m, st, _ := nativeFixture(t, a)
	data := largeHello(12000)
	p := parts(data, 1, 1000)[0]
	p = withNativeTimestamp(p)
	var b HelloBuffer
	_, out := e.BufferTCP(p, st, &b, m, time.Now())
	if out == nil || !out.Result.Modified {
		t.Fatal("large offload packet bypassed LOCAL", out)
	}
	r := out.Result
	got := make([]byte, len(data))
	seen := make([]bool, len(data))
	for i, q := range r.Packets {
		checkPacket(t, q)
		if len(q) > 1500 || r.PacketOrigins[i] != 0 {
			t.Fatal("invalid segmentation/address context")
		}
		if r.FakeAt(i) {
			continue
		}
		h := 20 + int(q[32]>>4)*4
		o := int(int32(binary.BigEndian.Uint32(q[24:]) - 1000))
		copy(got[o:], q[h:])
		for n := range q[h:] {
			seen[o+n] = true
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatal("LSO TLS bytes changed")
	}
	for _, v := range seen {
		if !v {
			t.Fatal("LSO hole")
		}
	}
}
func TestSYNDataDoesNotTouchTFOOrExistingData(t *testing.T) {
	p := &NativeTCPPlan{Mode: "syndata", Repeats: 1}
	base := packet(6, nil)
	base[33] = 2
	withTFO := append([]byte(nil), base...)
	withTFO = append(withTFO, 34, 2, 1, 1)
	withTFO[32] = 6 << 4
	binary.BigEndian.PutUint16(withTFO[2:], uint16(len(withTFO)))
	for _, q := range [][]byte{withTFO, packet(6, []byte("existing"))} {
		if r := nativeTCPSYN(q, &State{}, &compiled{}, p); r.Modified {
			t.Fatal("modified TFO/existing TCP")
		}
	}
}

func TestAllFlowsealTCPRulesRemainSelectableAfterCompilation(t *testing.T) {
	c := BundledCatalog()
	plans, caps := c.Compile()
	ids := map[string]bool{}
	for _, p := range plans {
		ids[p.ID] = true
	}
	tcpRules := map[string]bool{}
	for _, r := range c.Rules {
		if r.Source == "flowseal" {
			for _, a := range r.Applies {
				if a == "tcp443" {
					tcpRules[r.ID] = true
				}
			}
		}
	}
	for _, cap := range caps {
		if tcpRules[cap.Rule] && (!cap.Supported || !ids[cap.Plan]) {
			t.Fatal("rule is advertised but cannot be selected", cap.Rule, cap.Reason)
		}
	}
	if len(plans)+len(BrowserYouTubeCandidates()) > 64 {
		t.Fatal("candidate mask overflows")
	}
}
func TestNativeRecipeCannotEscapeBrowserTCP443Scope(t *testing.T) {
	actions, _ := compileNativeTCP(CatalogRule{Options: map[string][]string{"dpi-desync": {"fake"}, "dpi-desync-fooling": {"badseq"}}})
	for _, app := range []string{"cs2.exe", "TslGame.exe", "unrelated.exe"} {
		p := chainProfile(actions...)
		p.Preset = "browser-catalog"
		p.Application = app
		if _, e := compile(p); e == nil {
			t.Fatal("native browser recipe accepted unrelated app", app)
		}
	}
	p := chainProfile(actions...)
	p.Preset = "browser-catalog"
	p.Application = "chrome.exe"
	p.Ports = []uint16{3260}
	if _, e := compile(p); e == nil {
		t.Fatal("native recipe accepted iSCSI")
	}
}

func TestNativeFakedSplitReservesMD5HeaderForOffloadedHello(t *testing.T) {
	for _, mode := range []string{"fakedsplit", "fakeddisorder"} {
		a, reason := compileNativeTCP(CatalogRule{Options: map[string][]string{"dpi-desync": {mode}, "dpi-desync-fooling": {"md5sig"}, "dpi-desync-repeats": {"6"}}})
		if reason != "" {
			t.Fatal(reason)
		}
		e, m, st, _ := nativeFixture(t, a)
		data := largeHello(1955)
		p := withNativeTimestamp(parts(data, 1, 1000)[0])
		var b HelloBuffer
		_, out := e.BufferTCP(p, st, &b, m, time.Now())
		if out == nil || !out.Result.Modified {
			t.Fatal("offload MD5 fake exceeded MTU", mode, out)
		}
		for _, q := range out.Result.Packets {
			checkPacket(t, q)
			if len(q) > 1500 {
				t.Fatal("MTU", mode)
			}
		}
	}
}

func TestNativeRecipesEmitRequestedFakeAndRealOrder(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		alt        bool
		pattern    string
		descending bool
	}{
		{"fake,multisplit", false, "FFRR", false},
		{"fakedsplit", false, "FFRFFFFRFF", false},
		{"fakeddisorder", false, "FFRFFFFRFF", true},
		{"hostfakesplit", false, "RFFRFFR", false},
		{"hostfakesplit", true, "RFFRR", true},
	} {
		t.Run(tc.mode+tc.pattern, func(t *testing.T) {
			plan := &NativeTCPPlan{Mode: tc.mode, Repeats: 2, Fooling: "badseq", BadSequence: -10000, BadACK: -66000, Markers: []string{"1"}, Models: []NativeFakeModel{{Kind: "tls", Host: "www.google.com"}}, AlternateOrder: tc.alt}
			e, m, st, _ := nativeFixture(t, []Action{{Kind: "native-tcp443", Native: plan}})
			r := e.Process(parts(largeHello(512), 1, 1000)[0], st, m)
			if !r.Modified {
				t.Fatal("no transform")
			}
			var shape strings.Builder
			var offsets []int32
			for i, q := range r.Packets {
				if r.FakeAt(i) {
					shape.WriteByte('F')
				} else {
					shape.WriteByte('R')
					offsets = append(offsets, int32(binary.BigEndian.Uint32(q[24:])-1000))
				}
			}
			if shape.String() != tc.pattern {
				t.Fatalf("order=%s expected=%s", shape.String(), tc.pattern)
			}
			descending := false
			for i := 1; i < len(offsets); i++ {
				descending = descending || offsets[i] < offsets[i-1]
			}
			if descending != tc.descending {
				t.Fatal("real segment order", offsets)
			}
		})
	}
}

func TestNativeHostSplitAcceptsSNIEndingAtClientHelloBoundary(t *testing.T) {
	p := &NativeTCPPlan{Mode: "hostfakesplit", Repeats: 2, Fooling: "badseq", BadSequence: -10000, BadACK: -66000}
	e, m, st, _ := nativeFixture(t, []Action{{Kind: "native-tcp443", Native: p}})
	input := tlsInput(1000)
	data, _ := packetPayload(input, "tcp")
	start, size, ok := tlsSNI(data)
	if !ok || start+size != len(data) {
		t.Fatal("fixture does not end with SNI")
	}
	r := e.Process(input, st, m)
	if !r.Modified || r.FakePackets != 4 {
		t.Fatal("valid boundary SNI was rejected", r.Inspection)
	}
	for _, q := range r.Packets {
		checkPacket(t, q)
	}
}

func TestNativeSentPacketDiagnosticsReportActiveFoolingAndOriginalTTL(t *testing.T) {
	base := withNativeTimestamp(tlsInput(1000))
	base[8] = 128
	for _, mode := range []string{"ts", "badseq", "md5sig"} {
		plan := &NativeTCPPlan{Fooling: mode, BadSequence: -10000, BadACK: -66000, TimestampDelta: -600000}
		q := nativeTCPPacket(base, []byte{1, 2, 3}, 0, true, plan)
		if q == nil {
			t.Fatal(mode)
		}
		d := DescribeSentPacket(q, base)
		if d.TTL != 128 {
			t.Fatal("invented TTL change", mode, d)
		}
		if mode == "ts" && (d.TimestampDelta != -600000 || d.SequenceOffset != 0 || d.ACKOffset != 0) {
			t.Fatal("TS fake not accurately described", d)
		}
		if mode == "badseq" && (d.SequenceOffset != -10000 || d.ACKOffset != -66000) {
			t.Fatal("badseq/ack not applied", d)
		}
		if mode == "md5sig" && !d.MD5Present {
			t.Fatal("MD5 option missing", d)
		}
	}
}
