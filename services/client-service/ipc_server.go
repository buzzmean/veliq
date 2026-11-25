package clientservice

import (
	"context"
	"github.com/buzzmean/veliq/core/ipc"
	"net"
	"sync"
	"time"
)

func serveIPC(ctx context.Context, l net.Listener, server *ipc.Server) error {
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	defer wg.Wait()
	for {
		conn, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			request, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			server.Serve(request, conn)
		}()
	}
}
