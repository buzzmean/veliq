package localstrategy

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func largeHello(n int) []byte {
	p := bytes.ReplaceAll(fakeHello(), []byte("www.example.org"), []byte("www.youtube.com"))
	i := 44 + int(p[43])
	i += 2 + int(binary.BigEndian.Uint16(p[i:]))
	i += 1 + int(p[i])
	ext := int(binary.BigEndian.Uint16(p[i:]))
	padding := n - len(p) - 4
	if padding < 0 {
		panic("bad fixture")
	}
	p = append(p, 0, 21, byte(padding>>8), byte(padding))
	p = append(p, make([]byte, padding)...)
	binary.BigEndian.PutUint16(p[i:], uint16(ext+padding+4))
	binary.BigEndian.PutUint16(p[3:], uint16(len(p)-5))
	body := len(p) - 9
	p[6] = byte(body >> 16)
	p[7] = byte(body >> 8)
	p[8] = byte(body)
	return p
}
func segment(data []byte, seq uint32) []byte {
	p := packet(6, data)
	binary.BigEndian.PutUint32(p[24:], seq)
	binary.BigEndian.PutUint32(p[28:], 100)
	checksumTransport(p)
	return p
}
func assemblyProfile(actions []Action) Profile {
	p := chainProfile(actions...)
	p.IPs = nil
	p.Domains = []string{"www.youtube.com"}
	return p
}
func parts(data []byte, count int, seq uint32) [][]byte {
	out := [][]byte{}
	at := 0
	for i := 0; i < count; i++ {
		n := (len(data) - at) / (count - i)
		if i == 0 && count > 2 {
			n = 536
		}
		out = append(out, segment(data[at:at+n], seq+uint32(at)))
		at += n
	}
	return out
}
func assertStream(t *testing.T, r Result, original []byte, base uint32) {
	t.Helper()
	got := make([]byte, len(original))
	seen := make([]bool, len(original))
	for _, q := range r.Packets {
		checkPacket(t, q)
		payload, _ := packetPayload(q, "tcp")
		offset := int(int32(binary.BigEndian.Uint32(q[24:]) - base))
		if len(q) > 1500 {
			t.Fatal("giant TCP packet emitted")
		}
		if offset < 0 {
			if offset+len(payload) > 0 {
				t.Fatal("fake overlaps real stream")
			}
			continue
		}
		if offset+len(payload) > len(got) {
			t.Fatal("stream expanded")
		}
		for i, v := range payload {
			if seen[offset+i] && got[offset+i] != v {
				t.Fatal("conflicting output")
			}
			got[offset+i] = v
			seen[offset+i] = true
		}
	}
	for _, v := range seen {
		if !v {
			t.Fatal("stream hole")
		}
	}
	if !bytes.Equal(got, original) {
		t.Fatal("application bytes changed")
	}
}
func TestReassembledCandidatesAndModernHello(t *testing.T) {
	for _, candidate := range candidates() {
		for _, size := range []int{1923, 1955, 1987, 2019, 4096, 16000, 20000, 32758} {
			for _, count := range []int{2, 3, 5, 9, 16, 24, 32} {
				if (size+count-1)/count > 1460 || count > 2 && (size-536+count-2)/(count-1) > 1460 {
					continue
				}
				t.Run(candidate.ID+"/"+time.Duration(size).String()+"/"+time.Duration(count).String(), func(t *testing.T) {
					e := engine(t, assemblyProfile(candidate.Actions))
					base := uint32(0xffffff00)
					st := confirmed(e, base)
					b := &HelloBuffer{}
					data := largeHello(size)
					if size > 16384 {
						handshake := data[5:]
						data = nil
						for len(handshake) > 0 {
							n := 16000
							if n > len(handshake) {
								n = len(handshake)
							}
							data = append(data, 22, 3, 3, byte(n>>8), byte(n))
							data = append(data, handshake[:n]...)
							handshake = handshake[n:]
						}
					}
					input := parts(data, count, base)
					now := time.Now()
					var out *BufferedResult
					for i, p := range input {
						accepted, r := e.BufferTCP(p, st, b, metadata(), now.Add(time.Duration(i)*time.Millisecond))
						if !accepted {
							t.Fatal("not accepted")
						}
						if i < count-1 && r != nil {
							t.Fatal("premature decision", r.Result.Inspection)
						}
						out = r
					}
					if out == nil || !out.Result.Modified || out.Result.Inspection.Reason != "REASSEMBLY_COMPLETE" || out.Result.Domain != "www.youtube.com" {
						t.Fatal(out)
					}
					if out.Result.Inspection.ExpectedClientHelloBytes != size || b.Pending() || b.packets != nil || st.logicalHello != nil || st.helloPackets != nil {
						t.Fatal("bad bounds/retained payload")
					}
					for i, p := range out.Result.Packets {
						if len(p) > len(input[out.Result.PacketOrigins[i]]) && !(i == 0 && out.Result.FakePackets == 1) {
							t.Fatal("original segment enlarged")
						}
					}
					assertStream(t, out.Result, data, base)
				})
			}
		}
	}
}
func TestReassemblyRetransmitOutOfOrderAndRecordFraming(t *testing.T) {
	raw := largeHello(1955)
	hs := raw[5:]
	multi := []byte{}
	for _, span := range [][]byte{hs[:2], hs[2:44], hs[44:700], hs[700:]} {
		multi = append(multi, 22, 3, 3, byte(len(span)>>8), byte(len(span)))
		multi = append(multi, span...)
	}
	for _, data := range [][]byte{raw, multi} {
		for _, order := range [][]int{{0, 0, 1, 2}, {1, 0, 1, 2}, {2, 1, 0}, {0, 1, 2}} {
			e := engine(t, assemblyProfile(candidates()[1].Actions))
			st := confirmed(e, 10)
			b := &HelloBuffer{}
			input := parts(data, 3, 10)
			var out *BufferedResult
			for _, i := range order {
				_, out = e.BufferTCP(input[i], st, b, metadata(), time.Now())
				if out != nil {
					break
				}
			}
			if out == nil || !out.Result.Modified {
				t.Fatal("not assembled", order, out)
			}
			assertStream(t, out.Result, data, 10)
		}
	}
}
func TestReassemblyFailureBoundsAndDeadline(t *testing.T) {
	now := time.Now()
	data := largeHello(1955)
	for _, kind := range []string{"timeout", "deadline-complete", "conflict", "segment-limit", "byte-limit", "bad-length", "gap", "config-reload"} {
		t.Run(kind, func(t *testing.T) {
			e := engine(t, assemblyProfile(candidates()[0].Actions))
			st := confirmed(e, 123)
			b := &HelloBuffer{}
			first := segment(data[:536], 123)
			accepted, out := e.BufferTCP(first, st, b, metadata(), now)
			if !accepted || out != nil {
				t.Fatal("first fragment not held")
			}
			switch kind {
			case "timeout":
				v := b.Flush(st, "REASSEMBLY_TIMEOUT", now.Add(HelloDeadline))
				out = &v
			case "deadline-complete":
				_, out = e.BufferTCP(segment(data[536:], 659), st, b, metadata(), now.Add(HelloDeadline))
				if out == nil || !out.Result.Modified {
					t.Fatal("deadline final packet ignored")
				}
			case "conflict":
				p := append([]byte(nil), first...)
				p[50] ^= 1
				checksumTransport(p)
				_, out = e.BufferTCP(p, st, b, metadata(), now)
			case "segment-limit":
				for i := 0; i < MaxHelloSegments; i++ {
					_, out = e.BufferTCP(first, st, b, metadata(), now)
					if out != nil {
						break
					}
				}
			case "byte-limit":
				for i := 0; i < 32; i++ {
					_, out = e.BufferTCP(segment(make([]byte, 1400), 10000), st, b, metadata(), now)
					if out != nil {
						break
					}
				}
			case "bad-length":
				bad := append([]byte(nil), data...)
				bad[6] = 0xff
				_, out = e.BufferTCP(segment(bad[:536], 123), st, b, metadata(), now)
			case "gap":
				_, out = e.BufferTCP(segment(data[1000:], 1123), st, b, metadata(), now.Add(HelloDeadline))
			case "config-reload":
				if err := e.Reload(e.Config()); err != nil {
					t.Fatal(err)
				}
				_, out = e.BufferTCP(segment(data[536:], 659), st, b, metadata(), now)
			}
			if out == nil || b.Pending() || b.packets != nil {
				t.Fatal("buffer not released", out)
			}
			if kind != "deadline-complete" && out.Result.Modified {
				t.Fatal("unsafe transform")
			}
		})
	}
}
func TestReassemblyScopeAndConcurrentCleanup(t *testing.T) {
	e := engine(t, assemblyProfile(candidates()[0].Actions))
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := confirmed(e, 42)
			b := &HelloBuffer{}
			data := largeHello(1955)
			for _, p := range parts(data, 3, 42) {
				e.BufferTCP(p, st, b, metadata(), time.Now())
			}
			if b.Pending() {
				t.Error("retained")
			}
		}()
	}
	wg.Wait()
	for _, kind := range []string{"app", "port", "ipv6", "no-syn", "domain"} {
		st := confirmed(e, 42)
		b := &HelloBuffer{}
		m := metadata()
		switch kind {
		case "app":
			m.Application = "control.exe"
		case "port":
			m.Destination = netip.MustParseAddrPort("203.0.113.9:80")
		case "ipv6":
			m.Destination = netip.MustParseAddrPort("[2001:db8::1]:443")
		case "no-syn":
			st = &State{}
		}
		var out *BufferedResult
		accepted := false
		data := largeHello(1955)
		if kind == "domain" {
			data = bytes.ReplaceAll(data, []byte("www.youtube.com"), []byte("www.example.org"))
		}
		for _, p := range parts(data, 3, 42) {
			accepted, out = e.BufferTCP(p, st, b, m, time.Now())
		}
		if kind == "domain" {
			if out == nil || out.Result.Modified || out.Result.Inspection.Reason != "DOMAIN_NOT_MATCHED" {
				t.Fatal("domain gate bypassed", out)
			}
		} else if accepted || b.Pending() {
			t.Fatal("scope bypassed", kind)
		}
	}
}
func FuzzHelloRecordReassembly(f *testing.F) {
	f.Add(largeHello(1955))
	f.Add([]byte{22, 3, 3, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > MaxHelloBytes {
			p = p[:MaxHelloBytes]
		}
		h, offsets, _, _ := assembleHello(p)
		if h != nil {
			if len(h) > MaxHelloBytes || len(offsets) != len(h) {
				t.Fatal("unbounded parser")
			}
			for _, i := range offsets {
				if i < 0 || i >= len(p) {
					t.Fatal("invalid stream mapping")
				}
			}
		}
	})
}

func TestReassemblyIdenticalOverlapMalformedAndAfterDeadline(t *testing.T) {
	now := time.Now()
	data := largeHello(1955)
	for _, kind := range []string{"identical-overlap", "malformed-record", "malformed-handshake", "after-deadline", "excluded-domain", "unconfirmed-fake"} {
		t.Run(kind, func(t *testing.T) {
			p := assemblyProfile(candidates()[3].Actions)
			if kind == "excluded-domain" {
				p.ExcludeDomains = []string{"www.youtube.com"}
			}
			e := engine(t, p)
			st := confirmed(e, 200)
			if kind == "unconfirmed-fake" {
				st.handshakeConfirmed = false
			}
			b := &HelloBuffer{}
			raw := append([]byte(nil), data...)
			switch kind {
			case "malformed-record":
				raw[3] = 0xff
				raw[4] = 0xff
			case "malformed-handshake":
				raw[6] = 0xff
			}
			_, out := e.BufferTCP(segment(raw[:536], 200), st, b, metadata(), now)
			if out == nil {
				next := 536
				when := now
				if kind == "identical-overlap" {
					_, out = e.BufferTCP(segment(raw[400:1000], 600), st, b, metadata(), now)
					if out != nil {
						t.Fatal("identical overlap rejected")
					}
					next = 1000
				}
				if kind == "after-deadline" {
					when = now.Add(HelloDeadline + time.Nanosecond)
				}
				_, out = e.BufferTCP(segment(raw[next:], 200+uint32(next)), st, b, metadata(), when)
			}
			if out == nil || b.Pending() {
				t.Fatal("no decision/cleanup")
			}
			if kind == "identical-overlap" {
				if !out.Result.Modified {
					t.Fatal("valid overlap not transformed")
				}
				assertStream(t, out.Result, data, 200)
			} else if out.Result.Modified {
				t.Fatal("unsafe transform", kind)
			}
			if kind == "after-deadline" && out.Result.Inspection.Reason != "REASSEMBLY_TIMEOUT" {
				t.Fatal("late packet accepted")
			}
		})
	}
}
func FuzzTCPHelloSegments(f *testing.F) {
	f.Add(largeHello(1955), uint16(536))
	f.Add([]byte{22, 3, 3, 0xff, 0xff}, uint16(1))
	f.Fuzz(func(t *testing.T, data []byte, width uint16) {
		if len(data) > MaxHelloBytes {
			data = data[:MaxHelloBytes]
		}
		n := int(width)%1460 + 1
		e := engine(t, assemblyProfile(candidates()[3].Actions))
		st := confirmed(e, 0xfffffff0)
		b := &HelloBuffer{}
		now := time.Now()
		at := 0
		for i := 0; i < MaxHelloSegments+1 && at < len(data); i++ {
			end := at + n
			if end > len(data) {
				end = len(data)
			}
			accepted, out := e.BufferTCP(segment(data[at:end], 0xfffffff0+uint32(at)), st, b, metadata(), now)
			if out != nil {
				if out.Result.Modified {
					assertStream(t, out.Result, data[:end], 0xfffffff0)
				}
				break
			}
			if !accepted {
				break
			}
			at = end
		}
		if b.Pending() {
			b.Flush(st, "REASSEMBLY_TIMEOUT", now.Add(HelloDeadline))
		}
		if b.packets != nil {
			t.Fatal("payload retained")
		}
	})
}

func TestUnrelatedPresetReloadKeepsPendingYouTubeHello(t *testing.T) {
	entries, selected, err := PresetProfiles("youtube", `C:\Apps\chrome.exe`, true)
	if err != nil {
		t.Fatal(err)
	}
	e := New()
	if err = e.Reload(Config{Version: 1, Enabled: true, User: entries}); err != nil {
		t.Fatal(err)
	}
	// Observe a native SYN, then append another application's profiles while the
	// Chrome flow waits for payload. It must retain its original app generation.
	m := metadata()
	m.Application = `C:\Apps\chrome.exe`
	m.StrategyID = selected
	st := &State{}
	syn := packet(6, nil)
	syn[33] = 2
	e.Process(syn, st, m)
	before := st.applicationRevision
	discord, _, _ := PresetProfiles("discord", `C:\Apps\Discord.exe`, true)
	if err = e.Reload(Config{Version: 1, Enabled: true, User: append(entries, discord...)}); err != nil {
		t.Fatal(err)
	}
	if !e.bufferEligible(st, m) || st.applicationRevision != before || st.failed {
		t.Fatal("Discord update invalidated Chrome")
	}
}
func TestDeferredECHUsesOpaqueFallbackWithoutGuessingInner(t *testing.T) {
	p := append([]byte(nil), fakeHello()...)
	i := 44 + int(p[43])
	i += 2 + int(binary.BigEndian.Uint16(p[i:]))
	i += 1 + int(p[i])
	ext := int(binary.BigEndian.Uint16(p[i:]))
	p = append(p, 0xfe, 0x0d, 0, 0)
	binary.BigEndian.PutUint16(p[i:], uint16(ext+4))
	binary.BigEndian.PutUint16(p[3:], uint16(len(p)-5))
	handshake := len(p) - 9
	p[6] = byte(handshake >> 16)
	p[7] = byte(handshake >> 8)
	p[8] = byte(handshake)
	domain, reason, complete := InspectHelloStream(p)
	if !complete || domain != "www.example.org" || reason != "ECH_OUTER_SNI_ONLY" {
		t.Fatal(domain, reason, complete)
	}
	original := fakeHello()
	if _, why, ok := InspectHelloStream(original); !ok || why != "REASSEMBLY_COMPLETE" {
		t.Fatal("native parser changed", why)
	}
}
