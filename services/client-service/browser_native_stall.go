package clientservice

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

// Native forwarding never replays/migrates established traffic. Only future
// connections can consume a failure verdict. TLS headers/ServerHello metadata
// are observed passively: a five-byte alert/header is NOT a healthy handshake.
type nativeFirstReplyConn struct {
	net.Conn
	mu                          sync.Mutex
	timer                       *time.Timer
	sent, answered, closed, tls bool
	timeout                     time.Duration
	stalled                     func()
	failed                      func(string)
	wire                        browserproxy.TLSWireObserver
}

func (c *nativeFirstReplyConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.sent && len(p) > 0 {
		c.tls = p[0] == 22
	}
	if len(p) > 0 && !c.closed && !c.answered && c.timer == nil {
		c.sent = true
	}
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.wire.ObserveClient(p[:n])
		c.mu.Lock()
		if !c.closed && !c.answered && c.timer == nil {
			c.timer = time.AfterFunc(c.timeout, c.fail)
		}
		c.mu.Unlock()
	}
	if err != nil {
		c.failWithReason("DIRECT_WRITE_FAILED")
	}
	return n, err
}
func (c *nativeFirstReplyConn) fail() { c.failWithReason("DIRECT_FIRST_REPLY_TIMEOUT") }
func (c *nativeFirstReplyConn) failWithReason(reason string) {
	c.mu.Lock()
	if c.closed || c.answered || !c.sent {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.tls {
		reason = "DIRECT_TLS_" + strings.TrimPrefix(reason, "DIRECT_")
	}
	c.mu.Unlock()
	// Publish BEFORE closing the stream: reconnects must not outrun the cache.
	if c.failed != nil {
		c.failed(reason)
	}
	if c.stalled != nil {
		c.stalled()
	}
	c.Conn.Close()
}
func (c *nativeFirstReplyConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.wire.ObserveOrigin(p[:n])
		origin := c.wire.Snapshot().Origin
		c.mu.Lock()
		good := !c.tls || origin.ServerHelloComplete
		if good {
			c.answered = true
			if c.timer != nil {
				c.timer.Stop()
			}
		}
		badTLS := c.tls && (origin.State == "TLS_PLAINTEXT_ALERT_COMPLETE" || origin.State == "NON_TLS_OR_INVALID_HEADER")
		c.mu.Unlock()
		if badTLS {
			c.failWithReason("EARLY_ALERT_OR_INVALID_RECORD")
		}
	}
	if err != nil {
		// A harmless short read deadline is not a failed origin; the independent
		// first-response budget remains responsible for that verdict.
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			c.failWithReason("EARLY_EOF_OR_RESET")
		}
	}
	return n, err
}
func (c *nativeFirstReplyConn) Close() error {
	c.mu.Lock()
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return c.Conn.Close()
}
func (c *nativeFirstReplyConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
