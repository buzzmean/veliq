package localstrategy

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

const HTTP80HostSplit = "http80-host-split"
const MaxHTTP80HeaderBytes = 8 * 1024

// HTTP80Host accepts one complete origin-form HTTP/1 header. It returns only
// owned hostname storage, never a substring retaining cookies, URL or body.
func HTTP80Host(p []byte) (host string, cut, size int, complete bool) {
	return httpHeaderHost(p, false)
}

func httpHeaderHost(p []byte, otherPort bool) (host string, cut, size int, complete bool) {
	end := bytes.Index(p, []byte("\r\n\r\n"))
	if end < 0 {
		return "", 0, 0, len(p) >= MaxHTTP80HeaderBytes
	}
	size, complete = end+4, true
	if size > MaxHTTP80HeaderBytes {
		return "", 0, size, true
	}
	lines := bytes.Split(p[:end], []byte("\r\n"))
	first := bytes.Split(lines[0], []byte(" "))
	if len(first) != 3 || len(first[1]) == 0 || first[1][0] != '/' || !bytes.Equal(first[2], []byte("HTTP/1.1")) && !bytes.Equal(first[2], []byte("HTTP/1.0")) {
		return "", 0, size, true
	}
	switch string(first[0]) {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return "", 0, size, true
	}
	for _, b := range first[1] {
		if b <= 32 || b == 127 {
			return "", 0, size, true
		}
	}
	offset := len(lines[0]) + 2
	for _, line := range lines[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return "", 0, size, true
		}
		for _, b := range line[:colon] {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))) {
				return "", 0, size, true
			}
		}
		for _, b := range line[colon+1:] {
			if b < 32 && b != '\t' || b == 127 {
				return "", 0, size, true
			}
		}
		if bytes.EqualFold(line[:colon], []byte("Host")) {
			if host != "" {
				return "", 0, size, true
			}
			value := bytes.Trim(line[colon+1:], " \t")
			name := string(value)
			if colon := strings.LastIndexByte(name, ':'); colon >= 0 {
				port := name[colon+1:]
				n, err := strconv.ParseUint(port, 10, 16)
				if err != nil || n == 0 || !otherPort && port != "80" {
					return "", 0, size, true
				}
				name = name[:colon]
			}
			var err error
			host, err = domain(name)
			if err != nil || !strings.Contains(host, ".") {
				return "", 0, size, true
			}
			cut = offset + colon + 1 + bytes.Index(line[colon+1:], value) + 1
		}
		offset += len(line) + 2
	}
	return strings.Clone(host), cut, size, true
}

func (e *LocalStrategyEngine) http80Profile(m Metadata) bool {
	if m.Protocol != "tcp" || m.Destination.Port() != 80 {
		return false
	}
	for _, p := range e.current.Load().profiles {
		if p.Enabled && p.Strategy == HTTP80HostSplit && (m.StrategyID == "" || p.ID == m.StrategyID) && appMatch(p.Application, m.Application) {
			return true
		}
	}
	return false
}

// Split original TCP segments inside Host. No fake bytes, header rewriting or
// request replay. LSO input is bounded and emitted in <=1500-byte packets.
func http80Packets(packet []byte, st *State) Result {
	if !st.synSeen || !st.handshakeConfirmed || st.inspected != 1 {
		return Result{}
	}
	packets, header := st.helloPackets, st.logicalHello
	if len(packets) == 0 {
		packets = [][]byte{packet}
		header, _ = packetPayload(packet, "tcp")
	}
	host, cut, _, complete := HTTP80Host(header)
	if !complete || host == "" {
		return Result{}
	}
	out := Result{InputPackets: len(packets), ModifiedOrigins: make([]bool, len(packets)), Chain: HTTP80HostSplit}
	base := st.synSequence + 1
	for index, p := range packets {
		data, ok := packetPayload(p, "tcp")
		if !ok || len(data) == 0 || len(p) > MaxHelloBytes || p[33]&0x10 == 0 || p[33]&0x27 != 0 {
			return Result{}
		}
		h := len(p) - len(data)
		offset := int(int32(binary.BigEndian.Uint32(p[24:]) - base))
		if offset < 0 || offset+len(data) > MaxHelloBytes {
			return Result{}
		}
		for lo := 0; lo < len(data); {
			hi := min(len(data), lo+1500-h)
			if at := cut - offset; at > lo && at < hi {
				hi = at
			}
			part := nativeTCPPacket(p, data[lo:hi], lo, false, &NativeTCPPlan{})
			if part == nil || len(out.Packets) >= 64 {
				return Result{}
			}
			if hi < len(data) {
				part[33] &^= 8
			}
			if lo > 0 {
				part[33] &^= 0x80
			}
			checksumTransport(part)
			out.Packets = append(out.Packets, part)
			out.PacketOrigins = append(out.PacketOrigins, index)
			out.PacketFake = append(out.PacketFake, false)
			out.ModifiedOrigins[index] = out.ModifiedOrigins[index] || lo > 0 || hi < len(data)
			lo = hi
		}
		out.Modified = out.Modified || out.ModifiedOrigins[index]
	}
	return out
}
