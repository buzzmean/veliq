package clientservice

import (
	"io"
	"net"
	"sync"
	"time"
)

const browserVideoIdle = 20 * time.Second
const browserOpaqueGoogleIdle = 10 * time.Second
const browserRelayFirstIOIdle = 3 * time.Second

type relayMeterConn struct {
	net.Conn
	usage           *browserRelayUsage
	videoID         uint64
	profile, domain string
	release         func()
	once            sync.Once
	mu              sync.Mutex
	timer           *time.Timer
	idle            time.Duration
	deadline        time.Time
	generation      uint64
	closed, opaque  bool
	idleExpired     bool
}

func (c *relayMeterConn) resetIdleLocked(budget time.Duration) {
	if c.timer != nil {
		c.timer.Stop()
	}
	c.generation++
	generation := c.generation
	c.deadline = time.Now().Add(budget)
	c.timer = time.AfterFunc(budget, func() { c.expireIdle(generation) })
}
func (c *relayMeterConn) armIdle(first, active time.Duration, opaque bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.idle = active
	c.opaque = opaque
	c.resetIdleLocked(first)
}
func (c *relayMeterConn) expireIdle(generation uint64) {
	c.mu.Lock()
	if c.closed || generation != c.generation {
		c.mu.Unlock()
		return
	}
	if left := time.Until(c.deadline); left > 0 {
		c.timer = time.AfterFunc(left, func() { c.expireIdle(generation) })
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.idleExpired = true
	c.mu.Unlock()
	c.usage.mu.Lock()
	c.usage.admissionPool(c.opaque).idleClosed++
	c.usage.mu.Unlock()
	c.Close()
}
func (c *relayMeterConn) activity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil && !c.closed {
		c.resetIdleLocked(c.idle)
	}
}
func (c *relayMeterConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n == 0 && e != nil {
		c.mu.Lock()
		expired := c.idleExpired
		c.mu.Unlock()
		if expired {
			e = io.EOF
		}
	} // scheduled local idle close, not relay transport failure
	if n > 0 {
		c.activity()
		c.usage.accountIO(c.profile, c.domain, 0, uint64(n), time.Now(), c.videoID)
	}
	return n, e
}
func (c *relayMeterConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.activity()
		c.usage.accountIO(c.profile, c.domain, uint64(n), 0, time.Now(), c.videoID)
	}
	return n, e
}
func (c *relayMeterConn) Close() error {
	var err error
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		idle := c.idleExpired
		c.mu.Unlock()
		c.usage.videoClosed(c.videoID, idle)
		err = c.Conn.Close()
		c.release()
	})
	return err
}
func (c *relayMeterConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
