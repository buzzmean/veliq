package routing

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ErrUDPRecovering means this datagram was NOT delivered. Callers must account
// for loss, never replay it, and may send future packets on the same logical flow.
var ErrUDPRecovering = errors.New("protected UDP relay recovering")

type recoveringUDP struct {
	mu      sync.Mutex
	current Datagram
	closed  bool
	opening chan struct{}
	retryAt time.Time
	open    func(context.Context) (Datagram, error)
}

func (d *recoveringUDP) invalidate(current Datagram) {
	d.mu.Lock()
	if d.current == current {
		d.current = nil
		d.retryAt = time.Now().Add(100 * time.Millisecond)
	}
	d.mu.Unlock()
	current.Close()
}
func (d *recoveringUDP) get(ctx context.Context) (Datagram, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, errors.New("UDP flow closed")
	}
	if d.current != nil {
		c := d.current
		d.mu.Unlock()
		return c, nil
	}
	if d.opening != nil || time.Now().Before(d.retryAt) {
		d.mu.Unlock()
		return nil, ErrUDPRecovering
	}
	d.opening = make(chan struct{})
	d.mu.Unlock()
	attempt, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	c, err := d.open(attempt)
	cancel()
	d.mu.Lock()
	closed := d.closed
	if !closed && err == nil {
		d.current = c
	} else {
		d.retryAt = time.Now().Add(500 * time.Millisecond)
	}
	close(d.opening)
	d.opening = nil
	d.mu.Unlock()
	if closed {
		if c != nil {
			c.Close()
		}
		return nil, errors.New("UDP flow closed")
	}
	if err != nil {
		return nil, errors.Join(ErrUDPRecovering, err)
	}
	return c, nil
}
func (d *recoveringUDP) Send(b []byte) error {
	c, err := d.get(context.Background())
	if err != nil {
		return err
	}
	if err = c.Send(b); err != nil {
		d.invalidate(c)
		return errors.Join(ErrUDPRecovering, err)
	}
	return nil
}
func (d *recoveringUDP) Receive(ctx context.Context) ([]byte, error) {
	// Only outbound traffic establishes replacements. Never open/replay on reads.
	d.mu.Lock()
	c, closed := d.current, d.closed
	d.mu.Unlock()
	if closed {
		return nil, errors.New("UDP flow closed")
	}
	if c == nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
			return nil, ErrUDPRecovering
		}
	}
	b, err := c.Receive(ctx)
	var timeout net.Error
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &timeout) && timeout.Timeout()) {
		d.invalidate(c)
		return nil, errors.Join(ErrUDPRecovering, err)
	}
	return b, err
}
func (d *recoveringUDP) Close() error {
	d.mu.Lock()
	d.closed = true
	c := d.current
	d.current = nil
	d.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}
