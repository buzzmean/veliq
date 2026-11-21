package e2eprobe

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Controlled TCP echo uses the same authenticated, fixed-size nonce protocol.
// Bound sessions, frames and idle time; no anonymous payload reflector is added.
func ServeTCP(ctx context.Context, listener net.Listener, key []byte, stats *EchoStats) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	defer listener.Close()
	slots := make(chan struct{}, 16)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			stats.Rejected.Add(1)
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer conn.Close()
			cancel := context.AfterFunc(ctx, func() { conn.Close() })
			defer cancel()
			peer, err := netip.ParseAddrPort(conn.RemoteAddr().String())
			if err != nil || !peer.Addr().Unmap().Is4() {
				return
			}
			peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
			data := make([]byte, Size)
			for frame := 0; frame < 200; frame++ {
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.ReadFull(conn, data); err != nil {
					return
				}
				packet, err := Decode(data, key)
				if err != nil || packet.Reply {
					stats.Rejected.Add(1)
					return
				}
				packet.Reply = true
				packet.Peer = peer
				if _, err := io.Copy(conn, bytes.NewReader(Encode(packet, key))); err != nil {
					return
				}
				stats.Accepted.Add(1)
			}
		}()
	}
}
