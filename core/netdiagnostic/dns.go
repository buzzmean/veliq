// Package netdiagnostic performs bounded, credential-free, read-only probes.
// It never changes DNS, policy, routing, browser settings or TLS verification.
package netdiagnostic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"time"
)

type DNSResult struct {
	Host, Resolver, Transport, Result string
	AA, AD, Truncated                 bool
	RCode                             string
	Addresses                         []string
	MS                                float64
}

func dnsQuestion(host string) ([]byte, error) {
	n, e := dnsmessage.NewName(host + ".")
	if e != nil {
		return nil, e
	}
	var id [2]byte
	if _, e = rand.Read(id[:]); e != nil {
		return nil, e
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true})
	if e = b.StartQuestions(); e != nil {
		return nil, e
	}
	if e = b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); e != nil {
		return nil, e
	}
	return b.Finish()
}
func parseDNS(query, response []byte, r *DNSResult) error {
	var q, m dnsmessage.Message
	if q.Unpack(query) != nil || m.Unpack(response) != nil || !m.Header.Response || m.Header.ID != q.Header.ID || len(m.Questions) != 1 || m.Questions[0] != q.Questions[0] {
		return fmt.Errorf("DNS_RESPONSE_MISMATCH")
	}
	r.AA = m.Header.Authoritative
	r.AD = m.Header.AuthenticData
	r.Truncated = m.Header.Truncated
	r.RCode = m.Header.RCode.String()
	r.Result = "ANSWER"
	if m.Header.RCode != dnsmessage.RCodeSuccess {
		r.Result = r.RCode
	}
	for _, a := range m.Answers {
		if v, ok := a.Body.(*dnsmessage.AResource); ok {
			r.Addresses = append(r.Addresses, net.IP(v.A[:]).String())
		}
	}
	if r.Truncated {
		r.Result = "TRUNCATED"
	}
	return nil
}
func DNS(ctx context.Context, host, resolver, kind string) DNSResult {
	r := DNSResult{Host: host, Resolver: resolver, Transport: kind, Result: "UNAVAILABLE"}
	start := time.Now()
	if kind == "system" {
		addresses, err := net.DefaultResolver.LookupHost(ctx, host)
		r.Addresses = addresses
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				r.Result = "SYSTEM_NAME_NOT_FOUND"
			} else {
				r.Result = ErrorClass(err)
			}
		}
		if len(r.Addresses) > 0 {
			r.Result = "ANSWER"
		}
		r.MS = float64(time.Since(start)) / float64(time.Millisecond)
		return r
	}
	query, err := dnsQuestion(host)
	if err != nil {
		r.Result = "INVALID_HOST"
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var answer []byte
	if kind == "doh" {
		// Endpoint already used by browser DNS recovery. Dial pins IP, normal SNI/CA remain.
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "dns.google"}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(resolver, "443"))
		}}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://dns.google/dns-query", bytes.NewReader(query))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, e := client.Do(req)
		err = e
		if e == nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				err = fmt.Errorf("HTTP_STATUS")
			} else {
				answer, err = io.ReadAll(io.LimitReader(resp.Body, 65536))
			}
		}
	} else {
		port, network := "53", "tcp"
		if kind == "udp" {
			network = "udp"
		}
		if kind == "dot" {
			port = "853"
		}
		var c net.Conn
		c, err = (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(resolver, port))
		if err == nil {
			defer c.Close()
			deadline, _ := ctx.Deadline()
			_ = c.SetDeadline(deadline)
			if kind == "dot" {
				secure := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: resolver})
				err = secure.HandshakeContext(ctx)
				c = secure
			}
			if err == nil {
				if kind == "udp" {
					_, err = c.Write(query)
					if err == nil {
						buf := make([]byte, 65535)
						var n int
						n, err = c.Read(buf)
						answer = buf[:n]
					}
				} else {
					packet := make([]byte, 2+len(query))
					binary.BigEndian.PutUint16(packet, uint16(len(query)))
					copy(packet[2:], query)
					_, err = c.Write(packet)
					if err == nil {
						var header [2]byte
						_, err = io.ReadFull(c, header[:])
						if err == nil {
							answer = make([]byte, int(binary.BigEndian.Uint16(header[:])))
							_, err = io.ReadFull(c, answer)
						}
					}
				}
			}
		}
	}
	r.MS = float64(time.Since(start)) / float64(time.Millisecond)
	if err == nil {
		if parseDNS(query, answer, &r) != nil {
			r.Result = "INVALID_OR_MISMATCHED_DNS_RESPONSE"
		}
	} else {
		r.Result = ErrorClass(err)
	}
	return r
}
