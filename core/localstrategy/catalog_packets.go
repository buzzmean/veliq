package localstrategy

import (
	"crypto/rand"
	"encoding/binary"
	"path/filepath"
	"sort"
	"strings"
)

// Catalog profiles are an explicit, browser-only exception: <=20 packets per
// input packet overall, <=16 fakes per logical first ClientHello. Ordinary DIRECT+ keeps <=5 unchanged.
func catalogProfile(p Profile) bool {
	app := strings.ToLower(strings.ReplaceAll(p.Application, `\`, "/"))
	app = filepath.Base(app)
	if app != "chrome.exe" && app != "msedge.exe" && app != "brave.exe" && app != "browser.exe" && app != "opera.exe" && app != "firefox.exe" {
		return false
	}
	if p.Protocol != "tcp" || p.Cutoff != 1 {
		return false
	}
	for _, port := range p.Ports {
		if port != 443 && port != 80 {
			return false
		}
	}
	return true
}
func (s *State) ObserveServerTTL(ttl uint8) {
	if s.handshakeConfirmed && !s.failed {
		s.serverTTL = ttl
	}
}
func catalogTTL(a Action, s *State) uint8 {
	if !a.AutoTTL || s.serverTTL == 0 {
		return a.TTL
	}
	initial := uint16(64)
	if s.serverTTL > 64 {
		initial = 128
	}
	if s.serverTTL > 128 {
		initial = 255
	}
	hop := initial - uint16(s.serverTTL)
	if hop > 1 {
		hop--
	}
	if hop < 2 {
		hop = 2
	}
	if hop > 16 {
		hop = 16
	}
	return uint8(hop)
}
func catalogFake(p []byte, s *State, a Action) []byte {
	ttl := catalogTTL(a, s)
	q := oldSequenceFake(p, s, ttl)
	if q == nil {
		return nil
	}
	if a.FakeModel == "" && a.Fooling == "" {
		return q
	}
	data := q[40:]
	if a.FakeModel != "" {
		host := "www.google.com"
		if a.FakeModel == "tls13-yandex" {
			host = "ya.ru"
		}
		data = ownCatalogHello(host)
		if data == nil {
			return nil
		}
	}
	options := []byte{}
	if strings.Contains(a.Fooling, "ts") {
		options = append(options, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0)
	}
	if strings.Contains(a.Fooling, "md5sig") {
		signature := make([]byte, 16)
		if _, err := rand.Read(signature); err != nil {
			return nil
		}
		options = append(options, 19, 18)
		options = append(options, signature...)
		options = append(options, 1, 1)
	}
	out := make([]byte, 40+len(options)+len(data))
	copy(out, q[:40])
	copy(out[40:], options)
	copy(out[40+len(options):], data)
	out[32] = uint8((20+len(options))/4) << 4
	// Stronger old-sequence fooling is independent of TTL/PAWS/MD5 acceptance.
	// No fake byte can enter the receiving application's TCP sequence space.
	binary.BigEndian.PutUint32(out[24:], s.synSequence+1-uint32(len(data))-10000)
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	checksumTransport(out)
	return out
}

// Own TLS1.3-shaped model, no upstream binary/template or client session data.
func ownCatalogHello(host string) []byte { return ownCatalogHelloSize(host, 1250) }
func ownCatalogHelloSize(host string, total int) []byte {
	return ownCatalogHelloRandom(host, total, rand.Read)
}
func ownCatalogHelloRandom(host string, total int, fill func([]byte) (int, error)) []byte {
	body := make([]byte, 0, 1300)
	body = append(body, 3, 3)
	random := make([]byte, 64)
	if _, err := fill(random); err != nil {
		return nil
	}
	body = append(body, random[:32]...)
	body = append(body, 32)
	body = append(body, random[32:]...)
	body = append(body, 0, 6, 0x13, 1, 0x13, 2, 0x13, 3, 1, 0)
	ext := []byte{}
	add := func(kind uint16, data []byte) {
		ext = append(ext, byte(kind>>8), byte(kind), byte(len(data)>>8), byte(len(data)))
		ext = append(ext, data...)
	}
	sni := []byte{0, byte(3 + len(host)), 0, 0, byte(len(host))}
	sni = append(sni, host...)
	add(0, sni)
	add(43, []byte{2, 3, 4})
	add(10, []byte{0, 2, 0, 29})
	add(13, []byte{0, 4, 8, 4, 4, 3})
	public := make([]byte, 32)
	if _, err := fill(public); err != nil {
		return nil
	}
	share := append([]byte{0, 36, 0, 29, 0, 32}, public...)
	add(51, share)
	add(16, []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	padding := total - (5 + 4 + len(body) + 2 + len(ext) + 4)
	if padding < 0 {
		return nil
	}
	add(21, make([]byte, padding))
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...)
}
func catalogCuts(a Action, hello []byte) ([]int, bool) {
	start, size, hasSNI := tlsSNI(hello)
	out := []int{}
	for _, marker := range a.Markers {
		n := 0
		switch marker {
		case "1":
			n = 1
		case "2":
			n = 2
		case "midsld":
			if !hasSNI {
				return nil, false
			}
			name := string(hello[start : start+size])
			end := strings.LastIndex(name, ".")
			if end < 0 {
				end = size
			}
			begin := strings.LastIndex(name[:end], ".") + 1
			n = start + begin + (end-begin)/2
		case "sni+1":
			if !hasSNI {
				return nil, false
			}
			n = start + 1
		case "sniext+1":
			if !hasSNI || start < 9 {
				return nil, false
			}
			n = start - 8
		default:
			return nil, false
		}
		if n <= 0 || n >= len(hello) {
			return nil, false
		}
		out = append(out, n)
	}
	sort.Ints(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, false
		}
	}
	return out, true
}
func splitPayload(p, payload []byte, cuts []int) [][]byte {
	positions := append([]int{0}, cuts...)
	positions = append(positions, len(payload))
	out := [][]byte{}
	h := len(p) - len(payload)
	for i := 0; i+1 < len(positions); i++ {
		lo, hi := positions[i], positions[i+1]
		if hi <= lo || lo < 0 || hi > len(payload) {
			return nil
		}
		q := make([]byte, h+hi-lo)
		copy(q, p[:h])
		copy(q[h:], payload[lo:hi])
		if hi < len(payload) {
			q[33] &^= 8
		}
		if lo > 0 {
			q[33] &^= 0x80
		}
		binary.BigEndian.PutUint32(q[24:], binary.BigEndian.Uint32(p[24:])+uint32(lo))
		binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
		checksumTransport(q)
		out = append(out, q)
	}
	return out
}

// A real first fragment carries an old prefix followed by the unchanged stream.
// An RFC TCP receiver trims the duplicate prefix; no future sequence is forged.
func applySequenceOverlap(packets [][]byte, s *State, n uint16) bool {
	base := s.synSequence + 1
	for i, p := range packets {
		if binary.BigEndian.Uint32(p[24:]) != base {
			continue
		}
		data, ok := packetPayload(p, "tcp")
		if !ok {
			return false
		}
		header := len(p) - len(data)
		prefix := ownCatalogHelloSize("www.google.com", int(n))
		if prefix == nil || header+len(prefix)+len(data) > 1500 {
			return false
		}
		q := make([]byte, header+len(prefix)+len(data))
		copy(q, p[:header])
		copy(q[header:], prefix)
		copy(q[header+len(prefix):], data)
		binary.BigEndian.PutUint32(q[24:], base-uint32(n))
		binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
		checksumTransport(q)
		packets[i] = q
		return true
	}
	return false
}
