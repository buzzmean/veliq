// Package networklab applies deterministic delay and drops to real loopback UDP traffic.
package networklab

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Path struct {
	conn      *net.UDPConn
	done      chan struct{}
	packets   atomic.Uint64
	Delay     time.Duration
	DropEvery uint64
	closed    chan struct{}
	once      sync.Once
}

func Start(delay time.Duration, dropEvery uint64) (*Path, error) {
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		return nil, e
	}
	p := &Path{conn: c, done: make(chan struct{}), closed: make(chan struct{}), Delay: delay, DropEvery: dropEvery}
	go func() {
		defer close(p.done)
		b := make([]byte, 1500)
		for {
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			seq := p.packets.Add(1)
			if p.DropEvery > 0 && seq%p.DropEvery == 0 {
				continue
			}
			timer := time.NewTimer(p.Delay)
			select {
			case <-p.closed:
				timer.Stop()
				return
			case <-timer.C:
			}
			c.WriteToUDP(b[:n], a)
		}
	}()
	return p, nil
}
func (p *Path) Addr() net.Addr { return p.conn.LocalAddr() }
func (p *Path) Close()         { p.once.Do(func() { close(p.closed); p.conn.Close(); <-p.done }) }
