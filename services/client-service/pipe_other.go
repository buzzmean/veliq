//go:build !windows

package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/ipc"
	"net"
)

func ListenIPC(string) (net.Listener, error) {
	return nil, errors.New("Windows named pipe service requires Windows; use tools/demo for portable mode")
}
func ServeIPC(ctx context.Context, l net.Listener, server *ipc.Server) error {
	return serveIPC(ctx, l, server)
}
