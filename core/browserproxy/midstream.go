package browserproxy

import (
	"errors"
	"net"
	"sync"
	"time"
)

var ErrDirectMidstreamStall = errors.New("DIRECT_MIDSTREAM_STALL")

const DefaultMidstreamTimeout = 10 * time.Second

// WatchMidstream closes only this established DIRECT tunnel. It never reconnects,
// changes egress, retains payload or replays bytes. The browser may create a fresh
// connection; the caller records the failed domain/address for THAT next decision.
func WatchMidstream(conn net.Conn, timeout time.Duration, onStall func()) net.Conn {
	if timeout <= 0 {
		timeout = DefaultMidstreamTimeout
	}
	return &midstreamConn{Conn: conn, timeout: timeout, onStall: onStall}
}

type midstreamConn struct {
	net.Conn
	mu           sync.Mutex
	timeout      time.Duration
	progress     uint64
	answered     bool
	pending      time.Time
	readDeadline time.Time
	onStall      func()
	once         sync.Once
}

func (c *midstreamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	progress := c.progress
	c.mu.Unlock()
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		if c.answered && c.progress == progress && c.pending.IsZero() {
			c.pending = time.Now()
		}
		c.mu.Unlock()
	}
	return n, e
}
func (c *midstreamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}
func (c *midstreamConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}
func (c *midstreamConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		deadline, pending := c.readDeadline, c.pending
		c.mu.Unlock()
		wake := time.Now().Add(250 * time.Millisecond)
		if !pending.IsZero() && pending.Add(c.timeout).Before(wake) {
			wake = pending.Add(c.timeout)
		}
		if !deadline.IsZero() && deadline.Before(wake) {
			wake = deadline
		}
		c.Conn.SetReadDeadline(wake)
		n, e := c.Conn.Read(p)
		if n > 0 {
			c.mu.Lock()
			c.answered = true
			c.progress++
			c.pending = time.Time{}
			c.mu.Unlock()
			return n, e
		}
		if !isTimeout(e) {
			return n, e
		}
		c.mu.Lock()
		pending, deadline = c.pending, c.readDeadline
		c.mu.Unlock()
		if !pending.IsZero() && time.Since(pending) >= c.timeout {
			c.once.Do(func() {
				// Record the timeout before Close finalizes observers; otherwise
				// our own FIN can look like a neutral client shutdown.
				defer c.Conn.Close()
				if c.onStall != nil {
					c.onStall()
				}
			})
			return 0, ErrDirectMidstreamStall
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return n, e
		}
	}
}
func (c *midstreamConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
