package browserproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestFirstFlightFiniteDirectLocalRelayAndNoReplayAfterReply(t *testing.T) {
	for _, working := range []int{1, 2} {
		t.Run(string(rune('0'+working)), func(t *testing.T) {
			var attempts atomic.Int32
			var step func(int) net.Conn
			step = func(i int) net.Conn {
				attempts.Add(1)
				kind := "silent"
				if i == working {
					kind = "reply"
				}
				c := originFixture(t, kind, retryServerHello)
				if i == 2 {
					return c
				}
				return WatchFirstFlight(context.Background(), c, 15*time.Millisecond, func(context.Context) (net.Conn, error) { return step(i + 1), nil }, nil)
			}
			c := step(0)
			defer c.Close()
			if _, e := c.Write(retryHello); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, len(retryServerHello))
			if _, e := io.ReadFull(c, b); e != nil || !bytes.Equal(b, retryServerHello) {
				t.Fatal(e)
			}
			c.Read(make([]byte, 1))
			if attempts.Load() != int32(working+1) {
				t.Fatal("route replay after reply", attempts.Load())
			}
		})
	}
}
func TestFirstFlightLadderNeverReplaysAlertPartialHelloOrEarlyData(t *testing.T) {
	for _, flight := range [][]byte{retryHello[:7], append(append([]byte{}, retryHello...), 23, 3, 3, 0, 1, 1)} {
		var next atomic.Int32
		c := WatchFirstFlight(context.Background(), originFixture(t, "eof", nil), 10*time.Millisecond, func(context.Context) (net.Conn, error) { next.Add(1); return nil, errors.New("unexpected") }, nil)
		c.Write(flight)
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		c.Read(make([]byte, 32))
		c.Close()
		if next.Load() != 0 {
			t.Fatal("unsafe flight replayed")
		}
	}
	var next atomic.Int32
	alert := []byte{21, 3, 3, 0, 2, 2, 40}
	c := WatchFirstFlight(context.Background(), originFixture(t, "reply", alert), 10*time.Millisecond, func(context.Context) (net.Conn, error) { next.Add(1); return nil, errors.New("unexpected") }, nil)
	defer c.Close()
	c.Write(retryHello)
	got := make([]byte, len(alert))
	io.ReadFull(c, got)
	c.Read(make([]byte, 1))
	if next.Load() != 0 || !bytes.Equal(alert, got) {
		t.Fatal("alert hidden/replayed")
	}
}

func TestFirstFlightPartialServerReplyMarksFailureWithoutReplay(t *testing.T) {
	var next atomic.Int32
	var failed atomic.Int32
	c := WatchFirstFlight(context.Background(), originFixture(t, "reply", []byte{22}), 10*time.Millisecond, func(context.Context) (net.Conn, error) { next.Add(1); return nil, errors.New("unexpected") }, func(string) { failed.Add(1) })
	defer c.Close()
	if _, err := c.Write(retryHello); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if n, err := c.Read(b); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	c.Read(b)
	if next.Load() != 0 || failed.Load() == 0 {
		t.Fatal("partial reply replayed or unclassified", next.Load(), failed.Load())
	}
}
