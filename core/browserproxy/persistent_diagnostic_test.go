package browserproxy

import (
	"context"
	"io"
	"syscall"
	"testing"
)

func TestPersistentFirstConnectionFailureKeepsNativeCode(t *testing.T) {
	e := &tunnelCloseEvidence{ctx: context.Background()}
	e.terminal("upstream-read", syscall.Errno(10054))
	e.forcing.Store(true)
	e.terminal("client-write", syscall.Errno(10053))
	code, n, side := e.diagnostic()
	if code != "OS_ERROR" || n != 10054 || side != "UPSTREAM_READ" {
		t.Fatal(code, n, side)
	}
	e = &tunnelCloseEvidence{ctx: context.Background()}
	e.terminal("upstream-read", io.EOF)
	if code, _, _ := e.diagnostic(); code != "" {
		t.Fatal("ordinary EOF called a network failure")
	}
}
