package e2eprobe

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

type EchoStats struct{ Accepted, Rejected atomic.Uint64 }

// Replies never exceed request size; a shared token and rate cap prevent an open reflector.
func Serve(ctx context.Context, conn *net.UDPConn, key []byte, stats *EchoStats) error {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	b := make([]byte, Size+1)
	tokens := 200.
	last := time.Now()
	for {
		n, peer, err := conn.ReadFromUDPAddrPort(b)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		now := time.Now()
		tokens += now.Sub(last).Seconds() * 100
		if tokens > 200 {
			tokens = 200
		}
		last = now
		p, err := Decode(b[:n], key)
		if err != nil || p.Reply || !peer.Addr().Is4() || tokens < 1 {
			stats.Rejected.Add(1)
			continue
		}
		tokens--
		p.Reply = true
		p.Peer = peer
		if _, err = conn.WriteToUDPAddrPort(Encode(p, key), peer); err == nil {
			stats.Accepted.Add(1)
		}
	}
}
