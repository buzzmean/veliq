//go:build windows

package clientservice

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

// Only loopback sockets and in-memory profiles: no game, driver, OS proxy,
// registry, service, network adapter or user application is changed.
func TestWindowsDirectGameProxyFullAuthorityAndOwnerRecheck(t *testing.T) {
	for _, profileID := range []string{"steam", "cs2", "other-game"} {
		t.Run(profileID, func(t *testing.T) {
			c := New(context.Background())
			t.Cleanup(c.Close)
			id, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			c.BrowserOwnerSID, err = wp.ProcessUserSID(id)
			if err != nil {
				t.Fatal(err)
			}
			c.enabled, c.selfExecutable = true, "isolated-direct-service.exe"
			p := profiles.Profile{ID: profileID, Name: "Direct game fixture", Executables: []string{id.Path}, Mode: profiles.Direct, Custom: true}
			if err := c.Profiles.Upsert(p); err != nil {
				t.Fatal(err)
			}
			// Browser DNS deliberately offers a different, closed loopback address.
			c.BrowserResolver = continuityResolver(t, [4]byte{127, 0, 0, 2})
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			peerDone := make(chan error, 1)
			go func() {
				peer, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer peer.Close()
				_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = peer.Write([]byte("first-login-ready"))
				peerDone <- err
			}()
			q := browserproxy.Request{Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, Source: netip.MustParseAddrPort("127.0.0.1:55123"), Host: "localhost", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			plan, err := c.authorityPlan(ctx, q)
			if err != nil || plan.Enabled || plan.Policy.Action != flowpolicy.Direct || c.authorityWatchDirect(q, plan) {
				t.Fatal("game inherited browser path", plan, err)
			}
			conn, err := c.authorityOpen(ctx, q, plan)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			body, err := io.ReadAll(conn)
			conn.Close()
			if err != nil || string(body) != "first-login-ready" {
				t.Fatal("first connection stalled", string(body), err)
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
			q.Owner.Birth++
			if conn, err := c.authorityOpen(ctx, q, plan); err == nil {
				conn.Close()
				t.Fatal("reused/stale owner opened DIRECT")
			}
		})
	}
}
