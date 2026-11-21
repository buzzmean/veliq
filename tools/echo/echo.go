// Package echo provides loopback-only test destinations, never production services.
package echo

import (
	"io"
	"net"
	"sync"
)

func UDP() (net.Addr, func(), error) {
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		return nil, nil, e
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			c.WriteToUDP(b[:n], a)
		}
	}()
	return c.LocalAddr(), func() { c.Close(); <-done }, nil
}
func TCP() (net.Addr, func(), error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return nil, nil, e
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	all := map[net.Conn]bool{}
	closed := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				c.Close()
				return
			}
			all[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() { c.Close(); mu.Lock(); delete(all, c); mu.Unlock() }()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr(), func() {
		l.Close()
		mu.Lock()
		closed = true
		for c := range all {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}, nil
}
