package browserproxy

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// DefaultStallTimeout: how long a DIRECT origin may stay silent after the browser's
	// first bytes (ClientHello) before the tunnel is retried through the relay. A healthy
	// ServerHello arrives within a few hundred milliseconds; 2 s tolerates a congested
	// link while keeping the browser's own connect timeout out of the picture.
	DefaultStallTimeout = 2 * time.Second
	// maxReplay bounds what is remembered for replay. A TLS first flight is ~2 KB; a
	// tunnel that already sent more than this is not a stalled handshake.
	maxReplay = 64 * 1024
)

var errNoReplay = errors.New("first flight not replayable")

// stallConn wraps a DIRECT upstream. It records the client's bytes until the origin
// answers. If the origin stays silent for StallTimeout after the client's first byte,
// or resets the connection without a single byte, it asks onStall for a relay
// connection, replays the recorded first flight to it and carries on, so the browser
// never sees the failure. It is one-shot and only ever moves traffic TOWARDS the relay.
type stallConn struct {
	retryGate     sync.RWMutex
	handshakeOnly bool
	mu            sync.Mutex
	cur           net.Conn
	timeout       time.Duration
	firstAt       time.Time
	rec           []byte
	overflow      bool
	settled       bool
	retried       bool
	closed        bool
	halfClose     bool
	onStall       func(context.Context) (net.Conn, error)
	onSwap        func(stalled bool, retried bool, err error)
	answered      func()
	ctx           context.Context
}

func newStallConn(ctx context.Context, upstream net.Conn, timeout time.Duration, onStall func(context.Context) (net.Conn, error), onSwap func(bool, bool, error), answered func()) *stallConn {
	if timeout <= 0 {
		timeout = DefaultStallTimeout
	}
	return &stallConn{cur: upstream, timeout: timeout, onStall: onStall, onSwap: onSwap, answered: answered, ctx: ctx}
}

func (x *stallConn) current() net.Conn { x.mu.Lock(); defer x.mu.Unlock(); return x.cur }

func (x *stallConn) Write(p []byte) (int, error) {
	x.retryGate.RLock()
	defer x.retryGate.RUnlock()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return 0, net.ErrClosed
	}
	if !x.settled && len(p) > 0 {
		if x.firstAt.IsZero() {
			x.firstAt = time.Now()
		}
		if !x.overflow {
			if len(x.rec)+len(p) > maxReplay {
				x.overflow, x.rec = true, nil
			} else {
				x.rec = append(x.rec, p...)
			}
		}
	}
	x.cur.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return x.cur.Write(p)
}

func (x *stallConn) settle() {
	x.mu.Lock()
	x.settled, x.rec = true, nil
	x.mu.Unlock()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

func (x *stallConn) Read(p []byte) (int, error) {
	for {
		x.mu.Lock()
		cur, settled, first := x.cur, x.settled, x.firstAt
		x.mu.Unlock()
		if settled {
			cur.SetReadDeadline(time.Time{})
			return cur.Read(p)
		}
		wake := time.Now().Add(100 * time.Millisecond)
		if !first.IsZero() && first.Add(x.timeout).Before(wake) {
			wake = first.Add(x.timeout)
		}
		cur.SetReadDeadline(wake)
		n, err := cur.Read(p)
		if n > 0 {
			x.mu.Lock()
			direct := !x.retried
			x.mu.Unlock()
			x.settle()
			cur.SetReadDeadline(time.Time{})
			if direct && x.answered != nil {
				x.answered() // transport progress only, not verified HTTPS/site success
			}
			return n, nil
		}
		x.mu.Lock()
		first, closed := x.firstAt, x.closed
		x.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if err == nil {
			continue
		}
		if isTimeout(err) {
			if first.IsZero() || time.Since(first) < x.timeout {
				continue // the client has not spoken yet, or the origin still has time
			}
		} else if first.IsZero() {
			return 0, err // origin closed before the client said anything: not a stall
		}
		// Silent past the deadline, or reset/closed with zero bytes after the client's
		// first flight: the DIRECT path failed the same way a connect timeout does.
		x.mu.Lock()
		replayable := !x.overflow && !x.retried && len(x.rec) > 0 && (!x.handshakeOnly || clientHelloFlight(x.rec))
		x.mu.Unlock()
		if !replayable {
			x.settle()
			if x.handshakeOnly {
				return 0, errNoReplay
			}
			if isTimeout(err) {
				continue
			}
			return 0, err
		}
		if x.onSwap != nil {
			x.onSwap(true, false, nil)
		}
		// Release the failed Engine reservation before opening the same tuple on
		// another transport. Writers wait behind this bounded admission; they cannot
		// race an old socket close or write through a half-switched first flight.
		x.retryGate.Lock()
		cur.Close()
		next, serr := x.onStall(x.ctx)
		if serr != nil {
			x.retryGate.Unlock()
			x.settle()
			if x.onSwap != nil {
				x.onSwap(false, false, serr)
			}
			return 0, serr
		}
		if rerr := x.swap(next); rerr != nil {
			x.retryGate.Unlock()
			next.Close()
			x.settle()
			return 0, rerr
		}
		x.retryGate.Unlock()
		if x.onSwap != nil {
			x.onSwap(false, true, nil)
		}
	}
}

// swap replays the recorded first flight to next and makes it the live upstream. Writes
// are serialized with swap, so no client byte is lost or duplicated.
func (x *stallConn) swap(next net.Conn) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return net.ErrClosed
	}
	if x.overflow || len(x.rec) == 0 || x.handshakeOnly && !clientHelloFlight(x.rec) {
		return errNoReplay
	}
	next.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := next.Write(x.rec); err != nil {
		return err
	}
	if x.halfClose {
		if cw, ok := next.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	old := x.cur
	x.cur, x.retried, x.settled, x.rec = next, true, true, nil
	old.Close()
	return nil
}

func (x *stallConn) Close() error {
	x.mu.Lock()
	x.closed = true
	cur := x.cur
	x.mu.Unlock()
	return cur.Close()
}

// CloseWrite half-closes the live upstream; the request is remembered so a later swap
// (not possible after settle, but possible before) keeps the same half-closed state.
func (x *stallConn) CloseWrite() error {
	x.mu.Lock()
	x.halfClose = true
	cur := x.cur
	x.mu.Unlock()
	if cw, ok := cur.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (x *stallConn) LocalAddr() net.Addr                { return x.current().LocalAddr() }
func (x *stallConn) RemoteAddr() net.Addr               { return x.current().RemoteAddr() }
func (x *stallConn) SetDeadline(t time.Time) error      { return x.current().SetDeadline(t) }
func (x *stallConn) SetReadDeadline(t time.Time) error  { return x.current().SetReadDeadline(t) }
func (x *stallConn) SetWriteDeadline(t time.Time) error { return x.current().SetWriteDeadline(t) }
