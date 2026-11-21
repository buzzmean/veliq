package browserproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type DNSAnswer struct {
	Addresses  []netip.Addr
	TTL        time.Duration
	Source     string
	ObtainedAt time.Time
}
type DNSOpen func(context.Context, netip.AddrPort) (net.Conn, error)
type DNSLookup func(context.Context, string, DNSOpen) (DNSAnswer, error)
type dohProvider struct {
	host    string
	address netip.AddrPort
}
type DoHResolver struct {
	providers []dohProvider
	roots     *x509.CertPool
}

// Only resolver bootstrap IPs are fixed. Origin addresses are never hardcoded.
// The caller MUST open through an authenticated fail-closed relay policy.
func NewDoHResolver() *DoHResolver {
	return &DoHResolver{providers: []dohProvider{
		{"dns.google", netip.MustParseAddrPort("8.8.8.8:443")},
		{"cloudflare-dns.com", netip.MustParseAddrPort("1.1.1.1:443")},
	}}
}
func PublicDNSAddress(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "192.88.99.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(prefix).Contains(a) {
			return false
		}
	}
	return true
}
func dnsQuestion(host string) (dnsmessage.Name, []byte, error) {
	// Never send IP literals, single-label/LAN names or unbounded input to a public resolver.
	if len(host) > 253 || len(host) < 3 || host != strings.ToLower(host) || !strings.Contains(host, ".") {
		return dnsmessage.Name{}, nil, errors.New("DNS_NAME_INVALID")
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".home", ".internal", ".invalid", ".corp", ".localdomain", ".onion", ".home.arpa", ".test", ".example"} {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return dnsmessage.Name{}, nil, errors.New("DNS_NAME_PRIVATE")
		}
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return dnsmessage.Name{}, nil, errors.New("DNS_IP_LITERAL")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return dnsmessage.Name{}, nil, errors.New("DNS_NAME_INVALID")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return dnsmessage.Name{}, nil, errors.New("DNS_NAME_INVALID")
			}
		}
	}
	name, e := dnsmessage.NewName(host + ".")
	if e != nil {
		return name, nil, e
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	data, e := msg.Pack()
	return name, data, e
}
func decodeDNS(data []byte, name dnsmessage.Name) (DNSAnswer, error) {
	var msg dnsmessage.Message
	if len(data) < 12 || len(data) > 8192 || binary.BigEndian.Uint16(data[4:6]) != 1 || binary.BigEndian.Uint16(data[6:8]) > 64 || binary.BigEndian.Uint16(data[8:10]) > 16 || binary.BigEndian.Uint16(data[10:12]) > 16 || msg.Unpack(data) != nil || !msg.Header.Response || msg.Header.ID != 0 || msg.Header.OpCode != 0 || msg.Header.Truncated || msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 || msg.Questions[0].Name != name || msg.Questions[0].Type != dnsmessage.TypeA || msg.Questions[0].Class != dnsmessage.ClassINET || len(msg.Answers) > 64 {
		return DNSAnswer{}, errors.New("DNS_RESPONSE_INVALID")
	}
	current := strings.ToLower(name.String())
	ttl := uint32(300)
	seen := map[string]bool{}
	for hops := 0; hops < 8; hops++ {
		if seen[current] {
			return DNSAnswer{}, errors.New("DNS_CNAME_LOOP")
		}
		seen[current] = true
		out := DNSAnswer{}
		next := ""
		for _, rr := range msg.Answers {
			if strings.ToLower(rr.Header.Name.String()) != current || rr.Header.Class != dnsmessage.ClassINET {
				continue
			}
			switch body := rr.Body.(type) {
			case *dnsmessage.CNAMEResource:
				if next != "" && next != strings.ToLower(body.CNAME.String()) {
					return out, errors.New("DNS_CNAME_AMBIGUOUS")
				}
				next = strings.ToLower(body.CNAME.String())
				if rr.Header.TTL < ttl {
					ttl = rr.Header.TTL
				}
			case *dnsmessage.AResource:
				ip := netip.AddrFrom4(body.A)
				if !PublicDNSAddress(ip) {
					return out, errors.New("DNS_NONPUBLIC_ANSWER")
				}
				if rr.Header.TTL < ttl {
					ttl = rr.Header.TTL
				}
				duplicate := false
				for _, a := range out.Addresses {
					if a == ip {
						duplicate = true
					}
				}
				if !duplicate && len(out.Addresses) < 64 {
					out.Addresses = append(out.Addresses, ip)
				}
			}
		}
		if len(out.Addresses) > 0 {
			if next != "" {
				return out, errors.New("DNS_CNAME_AND_A")
			}
			out.TTL = time.Duration(ttl) * time.Second
			return out, nil
		}
		if next == "" {
			return out, errors.New("DNS_NO_A_ANSWER")
		}
		current = next
	}
	return DNSAnswer{}, errors.New("DNS_CNAME_LIMIT")
}
func (r *DoHResolver) Lookup(ctx context.Context, host string, open DNSOpen) (DNSAnswer, error) {
	name, data, err := dnsQuestion(host)
	if err != nil {
		return DNSAnswer{}, err
	}
	last := errors.New("DNS_DOH_UNAVAILABLE")
	for i, p := range r.providers {
		budget := 600 * time.Millisecond
		if d, ok := ctx.Deadline(); ok {
			remaining := time.Until(d) / time.Duration(len(r.providers)-i)
			if remaining < budget {
				budget = remaining
			}
		}
		sub, stop := context.WithTimeout(ctx, budget)
		answer, e := r.query(sub, p, data, name, open)
		stop()
		if e == nil {
			answer.Source = "RELAY_DOH_" + p.host
			answer.ObtainedAt = time.Now()
			return answer, nil
		}
		last = e
		if ctx.Err() != nil {
			break
		}
	}
	return DNSAnswer{}, last
}
func (r *DoHResolver) query(ctx context.Context, p dohProvider, data []byte, name dnsmessage.Name, open DNSOpen) (DNSAnswer, error) {
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192, TLSClientConfig: &tls.Config{ServerName: p.host, RootCAs: r.roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return open(ctx, p.address) }}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+p.host+"/dns-query", bytes.NewReader(data))
	if err != nil {
		return DNSAnswer{}, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return DNSAnswer{}, errors.New("DNS_DOH_TLS_OR_IO_FAILED")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || strings.Split(resp.Header.Get("Content-Type"), ";")[0] != "application/dns-message" {
		return DNSAnswer{}, errors.New("DNS_DOH_HTTP_FAILED")
	}
	wire, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil {
		return DNSAnswer{}, errors.New("DNS_DOH_BODY_FAILED")
	}
	answer, err := decodeDNS(wire, name)
	if err == nil {
		// HTTP cache Age consumes DNS TTL as well, never extend a stale answer.
		for _, directive := range strings.Split(strings.ToLower(resp.Header.Get("Cache-Control")), ",") {
			directive = strings.TrimSpace(directive)
			if directive == "no-store" || directive == "no-cache" {
				answer.TTL = 0
			}
			if strings.HasPrefix(directive, "max-age=") {
				seconds, e := strconv.ParseUint(strings.Trim(strings.TrimPrefix(directive, "max-age="), "\""), 10, 32)
				if e != nil {
					answer.TTL = 0
				} else if ttl := time.Duration(seconds) * time.Second; ttl < answer.TTL {
					answer.TTL = ttl
				}
			}
		}
		if raw := resp.Header.Get("Age"); raw != "" {
			seconds, e := strconv.ParseUint(raw, 10, 32)
			if e != nil {
				answer.TTL = 0
			} else {
				answer.TTL -= time.Duration(seconds) * time.Second
				if answer.TTL < 0 {
					answer.TTL = 0
				}
			}
		}
	}
	return answer, err
}

func ValidPublicDNSName(host string) bool { _, _, err := dnsQuestion(host); return err == nil }

// LookupAll merges independently authenticated provider answers for origin-IP
// repair. A syntactically valid but quarantined first provider's answer must not
// hide a working address returned by the other provider. Still max two queries,
// 64 unique public IPv4s, and the caller's SINGLE bounded deadline.
func (r *DoHResolver) LookupAll(ctx context.Context, host string, open DNSOpen) (DNSAnswer, error) {
	name, data, err := dnsQuestion(host)
	if err != nil {
		return DNSAnswer{}, err
	}
	out := DNSAnswer{Source: "RELAY_DOH_MULTIPROVIDER", ObtainedAt: time.Now(), TTL: 5 * time.Minute}
	last := errors.New("DNS_DOH_UNAVAILABLE")
	for i, p := range r.providers {
		budget := 600 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok {
			if share := time.Until(deadline) / time.Duration(len(r.providers)-i); share < budget {
				budget = share
			}
		}
		if budget <= 0 {
			break
		}
		sub, cancel := context.WithTimeout(ctx, budget)
		a, e := r.query(sub, p, data, name, open)
		cancel()
		if e != nil {
			last = e
			continue
		}
		if a.TTL < out.TTL {
			out.TTL = a.TTL
		}
		for _, ip := range a.Addresses {
			found := false
			for _, old := range out.Addresses {
				if old == ip {
					found = true
					break
				}
			}
			if !found && len(out.Addresses) < 64 {
				out.Addresses = append(out.Addresses, ip)
			}
		}
	}
	if len(out.Addresses) == 0 {
		return DNSAnswer{}, last
	}
	return out, nil
}
