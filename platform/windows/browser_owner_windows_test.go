//go:build windows

package windowsplatform

import (
	"github.com/buzzmean/veliq/core/routing"
	"net"
	"os"
	"os/exec"
	"testing"
)

func TestNativeChromeStaleAssociationCannotRecaptureServiceSocket(t *testing.T) {
	b, _ := captureFixture(t)
	child := exec.Command("ping.exe", "-n", "30", "127.0.0.1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	old, err := NewDiscovery().Lookup(uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	own, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	tuple := Tuple{Protocol: "tcp", Source: own.LocalAddr().(*net.TCPAddr).AddrPort(), Destination: own.RemoteAddr().(*net.TCPAddr).AddrPort()}
	b.associations.Put(Association{Identity: old, Tuple: tuple, Endpoint: 1})
	redirect := &tcpRedirect{b: b, port: 19000, state: newTCPState(32), delegated: map[Tuple]delegatedTCP{}, admission: newTCPAdmission()}
	p := tcpPacket(t, tuple)
	p[33] = 2
	var addr [80]byte
	addr[10] = 2
	redirect.processPacket(p, addr, func(ProcessIdentity, Tuple) Decision {
		t.Error("stale association classified service transport as Chrome")
		return Decision{Deferred: true, Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}
	})
	redirect.state.mu.Lock()
	defer redirect.state.mu.Unlock()
	e := redirect.state.entries[tuple]
	if e == nil || e.identity.PID != uint32(os.Getpid()) || e.mode != "direct" || e.decision.Deferred || !e.decision.Route.Direct() {
		t.Fatal("own socket recursively intercepted", e)
	}
}
