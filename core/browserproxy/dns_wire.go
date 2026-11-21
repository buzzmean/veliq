package browserproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const MaxDNSWire = 8192

type DNSHint struct {
	Name    string
	Address string
	TTL     uint32
}

// Only a single ordinary IN query is accepted. No updates, transfers or
// arbitrary opaque payload tunnelling through the authenticated DNS path.
func DNSQuestion(wire []byte) (dnsmessage.Question, error) {
	var m dnsmessage.Message
	if len(wire) < 12 || len(wire) > MaxDNSWire || binary.BigEndian.Uint16(wire[4:6]) != 1 || binary.BigEndian.Uint16(wire[6:8]) != 0 || binary.BigEndian.Uint16(wire[8:10]) != 0 || binary.BigEndian.Uint16(wire[10:12]) > 16 || m.Unpack(wire) != nil || m.Response || m.OpCode != 0 || len(m.Questions) != 1 || len(m.Answers) != 0 || len(m.Authorities) != 0 {
		return dnsmessage.Question{}, errors.New("BROWSER_DNS_QUERY_INVALID")
	}
	q := m.Questions[0]
	if q.Class != dnsmessage.ClassINET || q.Type == 251 || q.Type == 252 || q.Type == 255 {
		return q, errors.New("BROWSER_DNS_QUERY_UNSUPPORTED")
	}
	return q, nil
}

func DNSHost(q dnsmessage.Question) string {
	return strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
}

func ValidateDNSResponse(query, reply []byte) ([]DNSHint, error) {
	q, err := DNSQuestion(query)
	var m dnsmessage.Message
	if err != nil || len(reply) < 12 || len(reply) > MaxDNSWire || binary.BigEndian.Uint16(reply[6:8]) > 128 || binary.BigEndian.Uint16(reply[8:10]) > 128 || binary.BigEndian.Uint16(reply[10:12]) > 128 || m.Unpack(reply) != nil || !m.Response || m.ID != binary.BigEndian.Uint16(query[:2]) || m.OpCode != 0 || len(m.Questions) != 1 || !sameDNSQuestion(m.Questions[0], q) || len(m.Answers) > 128 {
		return nil, errors.New("BROWSER_DNS_RESPONSE_INVALID")
	}
	if m.Truncated || m.RCode != dnsmessage.RCodeSuccess {
		return nil, nil
	}
	name, ttl := q.Name, uint32(300)
	seen := map[dnsmessage.Name]bool{}
	for hop := 0; hop < 8; hop++ {
		if seen[name] {
			return nil, errors.New("BROWSER_DNS_CNAME_LOOP")
		}
		seen[name] = true
		var next dnsmessage.Name
		var out []DNSHint
		for _, rr := range m.Answers {
			if !strings.EqualFold(rr.Header.Name.String(), name.String()) || rr.Header.Class != dnsmessage.ClassINET {
				continue
			}
			if rr.Header.TTL < ttl {
				ttl = rr.Header.TTL
			}
			switch b := rr.Body.(type) {
			case *dnsmessage.CNAMEResource:
				if next.Length != 0 && next != b.CNAME {
					return nil, errors.New("BROWSER_DNS_CNAME_AMBIGUOUS")
				}
				next = b.CNAME
			case *dnsmessage.AResource:
				out = append(out, DNSHint{Name: DNSHost(q), Address: net.IP(b.A[:]).String()})
			case *dnsmessage.AAAAResource:
				out = append(out, DNSHint{Name: DNSHost(q), Address: net.IP(b.AAAA[:]).String()})
			}
		}
		if len(out) > 0 {
			if next.Length != 0 {
				return nil, errors.New("BROWSER_DNS_CNAME_AND_ADDRESS")
			}
			for i := range out {
				out[i].TTL = ttl
			}
			return out, nil
		}
		if next.Length == 0 {
			return nil, nil
		}
		name = next
	}
	return nil, errors.New("BROWSER_DNS_CNAME_LIMIT")
}

func DNSFailure(query []byte) []byte {
	q, err := DNSQuestion(query)
	if err != nil {
		return nil
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(query), Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: dnsmessage.RCodeServerFailure}, Questions: []dnsmessage.Question{q}}
	b, _ := m.Pack()
	return b
}

// Respect the client's UDP budget, capped below the IPv4 relay packet ceiling.
// Oversized DNSSEC/HTTPS answers prompt the already-supported TCP retry.
func DNSDatagramResponse(query, reply []byte) []byte {
	var request, response dnsmessage.Message
	if request.Unpack(query) != nil || response.Unpack(reply) != nil {
		return nil
	}
	budget := 512
	for _, rr := range request.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			budget = int(rr.Header.Class)
		}
	}
	if budget < 512 {
		budget = 512
	}
	if budget > 1232 {
		budget = 1232
	}
	if len(reply) <= budget {
		return reply
	}
	response.Header.Truncated = true
	response.Header.AuthenticData = false
	response.Answers = nil
	response.Authorities = nil
	response.Additionals = nil
	b, _ := response.Pack()
	return b
}

// Preserve ordinary resolver wire semantics, including NXDOMAIN and TC. No
// machine-wide DNS configuration or proxy environment is consulted/changed.
func ExchangeSystemDNS(ctx context.Context, network, destination string, query []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, destination)
	if err != nil {
		return nil, errors.New("BROWSER_DNS_SYSTEM_OPEN_FAILED")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if strings.HasPrefix(network, "tcp") {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		if _, err = io.Copy(conn, bytes.NewReader(append(size[:], query...))); err != nil {
			return nil, errors.New("BROWSER_DNS_SYSTEM_WRITE_FAILED")
		}
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return nil, errors.New("BROWSER_DNS_SYSTEM_READ_FAILED")
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n > MaxDNSWire || n < 12 {
			return nil, errors.New("BROWSER_DNS_RESPONSE_LIMIT")
		}
		b := make([]byte, n)
		_, err = io.ReadFull(conn, b)
		if err != nil {
			return nil, errors.New("BROWSER_DNS_SYSTEM_READ_FAILED")
		}
		return b, nil
	}
	if _, err = conn.Write(query); err != nil {
		return nil, errors.New("BROWSER_DNS_SYSTEM_WRITE_FAILED")
	}
	b := make([]byte, MaxDNSWire+1)
	n, err := conn.Read(b)
	if err != nil {
		return nil, errors.New("BROWSER_DNS_SYSTEM_READ_FAILED")
	}
	if n > MaxDNSWire {
		return nil, errors.New("BROWSER_DNS_RESPONSE_LIMIT")
	}
	return b[:n], nil
}

// TCP DNS framing is handled locally, without interpreting it as a ClientHello.
// No upstream socket is moved/replayed. Idle sockets and message size/count are bounded.
func NewDNSStream(parent context.Context, exchange func(context.Context, []byte) ([]byte, error)) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		stop := context.AfterFunc(parent, func() { server.Close() })
		defer stop()
		for messages := 0; messages < 64; messages++ {
			server.SetDeadline(time.Now().Add(5 * time.Second))
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(size[:]))
			if n < 12 || n > MaxDNSWire {
				return
			}
			query := make([]byte, n)
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(parent, 2*time.Second)
			reply, err := exchange(ctx, query)
			cancel()
			if err != nil {
				reply = DNSFailure(query)
			}
			if len(reply) == 0 || len(reply) > MaxDNSWire {
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
			if _, err = io.Copy(server, bytes.NewReader(append(size[:], reply...))); err != nil {
				return
			}
		}
	}()
	return client
}

func sameDNSQuestion(a, b dnsmessage.Question) bool {
	return a.Type == b.Type && a.Class == b.Class && strings.EqualFold(a.Name.String(), b.Name.String())
}
