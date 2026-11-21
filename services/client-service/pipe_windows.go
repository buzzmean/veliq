//go:build windows

package clientservice

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/buzzmean/neexitlag/core/ipc"
	"golang.org/x/sys/windows"
	"net"
	"time"
)

func ListenIPC(ownerSID string) (net.Listener, error) {
	if _, e := windows.StringToSid(ownerSID); e != nil {
		return nil, fmt.Errorf("invalid owner SID")
	}
	descriptor := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + ownerSID + ")"
	return winio.ListenPipe(`\\.\pipe\neexitlag-v1`, &winio.PipeConfig{SecurityDescriptor: descriptor, MessageMode: false, InputBufferSize: 65536, OutputBufferSize: 65536})
}
func ServeIPC(ctx context.Context, l net.Listener, server *ipc.Server) error {
	return serveIPC(ctx, l, server)
}

var _ = time.Second
