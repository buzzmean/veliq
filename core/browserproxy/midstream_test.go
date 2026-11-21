package browserproxy

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestMidstreamClosesOnlyAfterResponseAndUnansweredNextRequestWithoutReplay(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var marks atomic.Int32
	c := WatchMidstream(a, 40*time.Millisecond, func() { marks.Add(1) })
	go func() { b.Write([]byte("response")); buf := make([]byte, 32); b.Read(buf) }()
	buf := make([]byte, 32)
	if n, e := c.Read(buf); e != nil || string(buf[:n]) != "response" {
		t.Fatal(n, e)
	}
	if _, e := c.Write([]byte("next encrypted request")); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Read(buf); !errors.Is(e, ErrDirectMidstreamStall) {
		t.Fatal("not classified", e)
	}
	if marks.Load() != 1 {
		t.Fatal("not marked once")
	}
	if _, e := c.Read(buf); !errors.Is(e, net.ErrClosed) && e == nil {
		t.Fatal("closed socket resurrected")
	}
}
func TestMidstreamIdleReadDeadlineIsNotDomainFailure(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var marks atomic.Int32
	c := WatchMidstream(a, 20*time.Millisecond, func() { marks.Add(1) })
	c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	_, e := c.Read(make([]byte, 8))
	if !isTimeout(e) || marks.Load() != 0 {
		t.Fatal("idle flow or pre-response incorrectly condemned", e)
	}
}
func TestMidstreamProgressResetsPendingWithoutSocketReplacement(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var marks atomic.Int32
	c := WatchMidstream(a, 60*time.Millisecond, func() { marks.Add(1) })
	go func() {
		b.Write([]byte("initial"))
		buf := make([]byte, 8)
		for i := 0; i < 5; i++ {
			if _, e := b.Read(buf); e != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			b.Write([]byte("reply"))
		}
	}()
	buf := make([]byte, 8)
	c.Read(buf)
	for i := 0; i < 5; i++ {
		if _, e := c.Write([]byte("request")); e != nil {
			t.Fatal(e)
		}
		if _, e := c.Read(buf); e != nil {
			t.Fatal(e)
		}
	}
	if marks.Load() != 0 {
		t.Fatal("healthy progress closed")
	}
}
