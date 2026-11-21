package browserproxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// An ephemeral capability authorizes only this fixed health destination, never
// application traffic, an arbitrary proxy target, or a browser owner bypass.
func (s *Server) transportCheck(c net.Conn, r *http.Request, target string) bool {
	token := r.Header.Get("Veliq-Transport-Check")
	if token == "" {
		return false
	}
	if s.cfg.TransportCheck == nil {
		writeError(c, 403)
		return true
	}
	allowed, secret := s.cfg.TransportCheck()
	if len(secret) != 64 || subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 || r.Method != "CONNECT" || target != allowed || r.Header.Get("Neexitlag-Source") != "" {
		writeError(c, 403)
		return true
	}
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", allowed)
	if err != nil {
		writeError(c, 502)
		return true
	}
	defer upstream.Close()
	deadline := time.Now().Add(3 * time.Second)
	c.SetDeadline(deadline)
	upstream.SetDeadline(deadline)
	if _, err = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return true
	}
	done := make(chan struct{}, 1)
	go func() { io.Copy(upstream, io.LimitReader(c, 16384)); done <- struct{}{} }()
	io.Copy(c, io.LimitReader(upstream, 16384))
	c.Close()
	upstream.Close()
	<-done
	return true
}

// ProbeConnect proves a real CONNECT plus certificate-verified TLS/HTTP health
// response. A listening port or CONNECT 200 alone is deliberately insufficient.
func ProbeConnect(ctx context.Context, proxy, target, token string, tlsConfig *tls.Config) error {
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify || len(token) != 64 {
		return errors.New("TRANSPORT_CHECK_INVALID")
	}
	a, err := net.ResolveTCPAddr("tcp4", proxy)
	if err != nil || !a.IP.IsLoopback() {
		return errors.New("TRANSPORT_CHECK_INVALID")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", proxy)
	if err != nil {
		return errors.New("CONNECT_LISTENER_UNAVAILABLE")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nVeliq-Transport-Check: %s\r\n\r\n", target, target, token)
	reader := bufio.NewReaderSize(conn, 4096)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		return errors.New("CONNECT_CHECK_REJECTED")
	}
	if reader.Buffered() != 0 {
		return errors.New("CONNECT_CHECK_UNEXPECTED_BYTES")
	}
	secure := tls.Client(conn, tlsConfig.Clone())
	defer secure.Close()
	if err = secure.HandshakeContext(ctx); err != nil {
		return errors.New("CONNECT_CHECK_TLS_FAILED")
	}
	fmt.Fprintf(secure, "GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	res, err := http.ReadResponse(bufio.NewReaderSize(secure, 4096), &http.Request{Method: "GET"})
	if err != nil {
		return errors.New("CONNECT_CHECK_HTTP_FAILED")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	var health struct {
		Status string `json:"status"`
	}
	if err != nil || len(raw) > 4096 || res.StatusCode != 200 || json.Unmarshal(raw, &health) != nil || health.Status != "ok" {
		return errors.New("CONNECT_CHECK_HEALTH_FAILED")
	}
	return nil
}
