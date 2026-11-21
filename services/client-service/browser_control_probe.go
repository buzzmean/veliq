package clientservice

// Credential-free public service probes. These connections belong to the probe,
// never to a browser session. They do not decrypt or inspect browser traffic.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" // RFC6455 public handshake checksum, never device authentication.
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

type publicProbeConn struct {
	net.Conn
	received atomic.Uint64
}

func (c *publicProbeConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.received.Add(uint64(n))
	return n, e
}
func publicProbeHost(host string) bool {
	return host == "youtube.com" || host == "gateway.discord.gg" || host == "discord.gg" || host == "cdn.discordapp.com"
}
func localProbeSuccess(host string, p browserproxy.ProbeResult) bool {
	if p.Failure != "" || p.TLSVersion < tls.VersionTLS12 {
		return false
	}
	if host == "gateway.discord.gg" && p.Phase == "PUBLIC_WS_CONTROL" && p.Status == 101 && p.Detail == "THREE_NONCE_PONGS" {
		return true
	}
	if host == "youtube.com" && p.Phase == "PUBLIC_REDIRECT_CONTROL" && p.Status >= 300 && p.Status < 400 && p.Detail == "EXPECTED_YOUTUBE_REDIRECT" {
		return true
	}
	if host == "discord.gg" && p.Phase == "PUBLIC_REDIRECT_CONTROL" && p.Status >= 300 && p.Status < 400 && p.Detail == "EXPECTED_DISCORD_REDIRECT" {
		return true
	}
	return youtubeTransferOK(p)
}
func controlFailure(p browserproxy.ProbeResult, e error) browserproxy.ProbeResult {
	p.Failure = "PUBLIC_PROTOCOL_PROBE_FAILED"
	p.Detail = "PROTOCOL_OR_IO_FAILURE"
	var certificate *tls.CertificateVerificationError
	if errors.As(e, &certificate) {
		p.Failure = "TLS_CERTIFICATE_ERROR"
		p.Detail = "CERTIFICATE_VERIFICATION"
		return p
	}
	var timeout net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.As(e, &timeout) && timeout.Timeout() {
		p.Failure = "NETWORK_TIMEOUT"
		p.Detail = "DEADLINE"
	}
	if errors.Is(e, syscall.ECONNRESET) {
		p.Detail = "PEER_RESET"
	}
	if errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
		p.Detail = "PEER_CLOSED"
	}
	return p
}
func probePublicService(ctx context.Context, host string, roots *x509.CertPool, open func(context.Context) (net.Conn, error)) (p browserproxy.ProbeResult) {
	p.Phase = "RELAY_OR_TCP_OPEN"
	conn, e := open(ctx)
	if e != nil {
		return controlFailure(p, e)
	}
	defer conn.Close()
	wire := &publicProbeConn{Conn: conn}
	defer func() { p.Bytes = wire.received.Load() }()
	deadline := time.Now().Add(4 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	secure := tls.Client(wire, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	p.Phase = "ORIGIN_TLS"
	if e = secure.HandshakeContext(ctx); e != nil {
		return controlFailure(p, e)
	}
	p.TLSVersion = secure.ConnectionState().Version
	p.ALPN = secure.ConnectionState().NegotiatedProtocol
	reader := bufio.NewReader(io.LimitReader(secure, 256*1024))
	if host == "gateway.discord.gg" {
		return probeGatewayControl(ctx, host, secure, reader, p)
	}
	paths := []string{"/"}
	if host == "cdn.discordapp.com" {
		paths = nil
		for i := 0; i < 64; i++ {
			paths = append(paths, "/embed/avatars/"+string(rune('0'+i%6))+".png")
		}
	}
	p.Phase = "ORIGIN_HTTP"
	for _, path := range paths {
		req, e := http.NewRequestWithContext(ctx, "GET", "https://"+host+path, nil)
		if e != nil {
			return controlFailure(p, e)
		}
		req.Header.Set("Connection", "keep-alive")
		if e = req.Write(secure); e != nil {
			return controlFailure(p, e)
		}
		response, e := http.ReadResponse(reader, req)
		if e != nil {
			return controlFailure(p, e)
		}
		p.Status = response.StatusCode
		if (host == "discord.gg" || host == "youtube.com") && p.Status >= 300 && p.Status < 400 {
			target, e := response.Location()
			response.Body.Close()
			if e == nil && target.Scheme == "https" && target.User == nil && ((host == "discord.gg" && (target.Host == "discord.com" || target.Host == "www.discord.com")) || (host == "youtube.com" && target.Host == "www.youtube.com")) {
				p.Phase = "PUBLIC_REDIRECT_CONTROL"
				p.Detail = "EXPECTED_DISCORD_REDIRECT"
				if host == "youtube.com" {
					p.Detail = "EXPECTED_YOUTUBE_REDIRECT"
				}
				return p
			}
			p.Failure = "UNEXPECTED_REDIRECT"
			return p
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
		response.Body.Close()
		p.BodyBytes += uint64(len(body))
		if e != nil {
			return controlFailure(p, e)
		}
		if p.Status != 200 || host == "cdn.discordapp.com" && !bytes.HasPrefix(body, []byte{137, 'P', 'N', 'G', 13, 10, 26, 10}) {
			p.Failure = "UNEXPECTED_PUBLIC_ASSET_RESPONSE"
			return p
		}
		if p.BodyBytes > 64*1024 {
			return p
		}
	}
	p.Failure = "PUBLIC_PROBE_BUDGET_NOT_SUSTAINED"
	return p
}
func probeGatewayControl(ctx context.Context, host string, conn net.Conn, reader *bufio.Reader, p browserproxy.ProbeResult) browserproxy.ProbeResult {
	p.Phase = "PUBLIC_WS_CONTROL"
	key := make([]byte, 16)
	if _, e := rand.Read(key); e != nil {
		return controlFailure(p, e)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	req, e := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/?v=10&encoding=json", nil)
	if e != nil {
		return controlFailure(p, e)
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", encoded)
	req.Header.Set("Sec-WebSocket-Version", "13")
	if e = req.Write(conn); e != nil {
		return controlFailure(p, e)
	}
	response, e := http.ReadResponse(reader, req)
	if e != nil {
		return controlFailure(p, e)
	}
	p.Status = response.StatusCode
	sum := sha1.Sum([]byte(encoded + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if p.Status != 101 || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") || !headerHasToken(response.Header.Get("Connection"), "upgrade") || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		p.Failure = "INVALID_WEBSOCKET_UPGRADE"
		return p
	}
	opcode, body, e := readPublicWSFrame(reader)
	p.BodyBytes += uint64(len(body))
	if e != nil {
		return controlFailure(p, e)
	}
	var hello struct {
		Op   int `json:"op"`
		Data struct {
			Interval float64 `json:"heartbeat_interval"`
		} `json:"d"`
	}
	if opcode != 1 || json.Unmarshal(body, &hello) != nil || hello.Op != 10 || hello.Data.Interval <= 0 {
		p.Failure = "INVALID_PUBLIC_GATEWAY_HELLO"
		return p
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			timer := time.NewTimer(200 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return controlFailure(p, ctx.Err())
			case <-timer.C:
			}
		}
		nonce := make([]byte, 32)
		if _, e = rand.Read(nonce); e != nil {
			return controlFailure(p, e)
		}
		if e = writePublicWSPing(conn, nonce); e != nil {
			return controlFailure(p, e)
		}
		matched := false
		for n := 0; n < 4; n++ {
			op, data, e := readPublicWSFrame(reader)
			p.BodyBytes += uint64(len(data))
			if e != nil {
				return controlFailure(p, e)
			}
			if op == 10 {
				if !bytes.Equal(data, nonce) {
					p.Failure = "WRONG_WEBSOCKET_NONCE"
					return p
				}
				matched = true
				break
			}
			if op == 8 {
				p.Failure = "GATEWAY_CLOSED_BEFORE_PROOF"
				return p
			}
		}
		if !matched {
			p.Failure = "NO_WEBSOCKET_PONG"
			return p
		}
	}
	p.Detail = "THREE_NONCE_PONGS"
	return p
}
func headerHasToken(s, want string) bool {
	for _, v := range strings.Split(s, ",") {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}
func writePublicWSPing(w io.Writer, data []byte) error {
	if len(data) > 125 {
		return errors.New("control frame limit")
	}
	mask := make([]byte, 4)
	if _, e := rand.Read(mask); e != nil {
		return e
	}
	p := []byte{0x89, 0x80 | byte(len(data))}
	p = append(p, mask...)
	for i, b := range data {
		p = append(p, b^mask[i%4])
	}
	_, e := w.Write(p)
	return e
}
func readPublicWSFrame(r io.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return 0, nil, e
	}
	if header[0]&0x80 == 0 || header[0]&0x70 != 0 || header[1]&0x80 != 0 {
		return 0, nil, errors.New("unsupported public frame")
	}
	n := uint64(header[1] & 127)
	if n == 126 {
		var b [2]byte
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, nil, e
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	} else if n == 127 {
		return 0, nil, errors.New("public frame limit")
	}
	if n > 16*1024 {
		return 0, nil, errors.New("public frame limit")
	}
	data := make([]byte, n)
	_, e := io.ReadFull(r, data)
	return header[0] & 15, data, e
}
