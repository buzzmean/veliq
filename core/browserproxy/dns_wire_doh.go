package browserproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ExchangeWire resolves on the VPS egress using ordinary HTTPS DoH. The existing
// relay needs no new endpoint/configuration. TLS validation stays enabled. Raw
// DNS/53 is NEVER sent to the relay; only authenticated TCP/443 to a fixed resolver.
// Preserve AAAA/HTTPS/SVCB/DNSSEC wire records instead of stripping ECH metadata.
// Caller authorizes recovery for this name/profile; ordinary DNS stays outside
// this path. A valid NXDOMAIN/SERVFAIL may be retried at the next trusted provider.
func (r *DoHResolver) ExchangeWire(ctx context.Context, query []byte, open DNSOpen) ([]byte, error) {
	q, err := DNSQuestion(query)
	if err != nil {
		return nil, err
	}
	if !ValidPublicDNSName(DNSHost(q)) {
		return nil, errors.New("BROWSER_DNS_PUBLIC_NAME_REQUIRED")
	}
	parent := ctx
	ctx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	var negative []byte
	wire := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(wire, 0)
	for i, p := range r.providers {
		if ctx.Err() != nil {
			break
		}
		budget := time.Second
		if d, ok := ctx.Deadline(); ok {
			if left := time.Until(d) / time.Duration(len(r.providers)-i); left < budget {
				budget = left
			}
		}
		sub, cancel := context.WithTimeout(ctx, budget)
		tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192, TLSClientConfig: &tls.Config{ServerName: p.host, RootCAs: r.roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return open(ctx, p.address) }}
		req, _ := http.NewRequestWithContext(sub, "POST", "https://"+p.host+"/dns-query", bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, e := tr.RoundTrip(req)
		var answer []byte
		if e == nil {
			if resp.StatusCode == 200 && strings.Split(resp.Header.Get("Content-Type"), ";")[0] == "application/dns-message" {
				answer, e = io.ReadAll(io.LimitReader(resp.Body, MaxDNSWire+1))
			} else {
				e = errors.New("BROWSER_DNS_DOH_HTTP_FAILED")
			}
			resp.Body.Close()
		}
		tr.CloseIdleConnections()
		cancel()
		if e != nil {
			continue
		}
		if _, e = ValidateDNSResponse(wire, answer); e != nil {
			continue
		}
		// A cached HTTP answer consumes DNS TTL too (RFC 8484).
		if raw := resp.Header.Get("Age"); raw != "" {
			age, e := strconv.ParseUint(raw, 10, 32)
			if e != nil {
				continue
			}
			var m dnsmessage.Message
			if m.Unpack(answer) != nil {
				continue
			}
			for _, rows := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
				for i := range rows {
					if rows[i].Header.Type == dnsmessage.TypeOPT {
						continue
					}
					if uint64(rows[i].Header.TTL) > age {
						rows[i].Header.TTL -= uint32(age)
					} else {
						rows[i].Header.TTL = 0
					}
				}
			}
			answer, e = m.Pack()
			if e != nil {
				continue
			}
		}
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		binary.BigEndian.PutUint16(answer, binary.BigEndian.Uint16(query))
		status := DNSResponseStatus(query, answer)
		if status == "DNS_NXDOMAIN" || status == "DNS_SERVFAIL" {
			// Сохраняем первый проверенный ответ, если ни один provider не восстановит имя.
			// NODATA, REFUSED и TC не означают отказ имени и не запускают этот повтор.
			if negative == nil {
				negative = answer
			}
			continue
		}
		return answer, nil
	}
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	if negative != nil {
		return negative, nil
	}
	return nil, errors.New("BROWSER_DNS_RELAY_DOH_FAILED")
}
