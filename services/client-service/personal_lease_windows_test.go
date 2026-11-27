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
	wp "github.com/buzzmean/veliq/platform/windows"
)

// A real Windows process identity and loopback socket exercise the final OPEN,
// without service/registry/capture changes or an external connection.
func TestPersonalStageLeaseNativeOpenKeepsUnselectedPlainDirect(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.enabled, c.selfExecutable = true, "different-test-service.exe"
	id, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := discoveredApplication(id)
	if !ok {
		t.Fatal("test identity unavailable")
	}
	c.configurePersonalLeaseStage(true) // No granted lease, no background worker.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	answered := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			answered <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("ordinary-direct"))
		answered <- err
	}()
	dst := netip.MustParseAddrPort(listener.Addr().String())
	q := browserproxy.Request{Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, Ingress: "AUTOMATIC_TCP", Source: netip.MustParseAddrPort("127.0.0.1:55124"), Host: "ordinary.example.org", Port: dst.Port()}
	plan := browserproxy.Plan{Enabled: true, Destination: dst, Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: "auto_direct_default"}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := c.browserOpen(ctx, q, plan)
	if err != nil {
		t.Fatal("expired stage lease blocked ordinary OS socket", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "ordinary-direct" {
		t.Fatal(string(data), err)
	}
	if err := <-answered; err != nil {
		t.Fatal(err)
	}
	provider := &unwantedGameRelay{}
	c.Engine.SetRelay("VPS-01", provider)
	q.Host = "chatgpt.com"
	plan.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}
	if conn, err := c.browserOpen(ctx, q, plan); err == nil || conn != nil || provider.calls.Load() != 0 {
		t.Fatal("protected managed OPEN reached relay without lease", err, provider.calls.Load())
	}
}
