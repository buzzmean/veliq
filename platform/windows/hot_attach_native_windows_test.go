//go:build windows

package windowsplatform

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/routing"
	"golang.org/x/sys/windows"
)

func TestHotAttachSocketChild(t *testing.T) {
	target := os.Getenv("VELIQ_HOT_CHILD_TARGET")
	if target == "" {
		t.Skip("owned native helper")
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp4", target, time.Second)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		fmt.Println("CONNECTED", c.LocalAddr().String())
		buf := []byte{1}
		for {
			c.SetDeadline(time.Now().Add(time.Second))
			if _, err = c.Write(buf); err != nil {
				break
			}
			if _, err = io.ReadFull(c, buf); err != nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		c.Close()
	}
	t.Fatal("parent did not stop owned fixture")
}
func TestNativeHotAttachExactSocketResetWithoutProcessRestart(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("native service reset requires elevated token")
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	start := func() (*exec.Cmd, <-chan string) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHotAttachSocketChild$", "-test.v")
		cmd.Env = append(os.Environ(), "VELIQ_HOT_CHILD_TARGET="+l.Addr().String())
		pipe, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		lines := make(chan string, 16)
		go func() {
			defer close(lines)
			scanner := bufio.NewScanner(pipe)
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "CONNECTED ") {
					select {
					case lines <- strings.TrimPrefix(scanner.Text(), "CONNECTED "):
					default:
					}
				}
			}
		}()
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		return cmd, lines
	}
	selected, selectedLines := start()
	control, controlLines := start()
	next := func(lines <-chan string) string {
		select {
		case line := <-lines:
			if line == "" {
				t.Fatal("helper exited")
			}
			return line
		case <-time.After(5 * time.Second):
			t.Fatal("no automatic reconnect")
			return ""
		}
	}
	first := next(selectedLines)
	_ = next(controlLines)
	discovery := NewDiscovery()
	id, err := discovery.Lookup(uint32(selected.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	controlID, err := discovery.Lookup(uint32(control.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := queryOwnedTCP()
	if err != nil {
		t.Fatal(err)
	}
	var row ownedTCPRow
	found := false
	for _, r := range rows {
		if r.PID == id.PID && r.Tuple.Source.String() == first && r.Tuple.Destination.String() == l.Addr().String() {
			row = r
			found = true
			break
		}
	}
	if !found {
		t.Fatal("selected exact socket unavailable")
	}
	if err = resetOwnedTCP(row, controlID); err == nil {
		t.Fatal("foreign owner accepted")
	}
	stale := id
	stale.CreationTime++
	if err = resetOwnedTCP(row, stale); err == nil {
		t.Fatal("PID reuse accepted")
	}
	if err = resetOwnedTCP(row, id); err != nil {
		t.Fatal(err)
	}
	_ = next(selectedLines)
	if !IsCurrent(id) || !IsCurrent(controlID) {
		t.Fatal("process restarted/exited")
	}
	select {
	case line := <-controlLines:
		t.Fatal("unrelated DIRECT connection reset", line)
	case <-time.After(250 * time.Millisecond):
	}
	// Repeat: normal user enable -> disable -> re-enable can reset a new socket
	// in the same still-running application; never replay the old stream.
	rows, err = queryOwnedTCP()
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, r := range rows {
		if r.PID == id.PID && r.Tuple.Destination.String() == l.Addr().String() {
			row = r
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fresh socket missing")
	}
	if err = resetOwnedTCP(row, id); err != nil {
		t.Fatal(err)
	}
	_ = next(selectedLines)
	if !IsCurrent(id) {
		t.Fatal("process restart required")
	}
	t.Log("native Windows exact IPv4 TCP reset: same selected/control PID+birth; automatic reconnect twice; unrelated live socket unchanged")
}
func TestNativeHotAttachUDPReconfigureRetiresOnlySelected(t *testing.T) {
	b, _ := captureFixture(t)
	b.dll = &divertDLL{}
	dest := netip.MustParseAddrPort("1.1.1.1:53")
	tuple, f := startCaptureTestFlow(t, b, 45001, false, dest, "selected")
	_, control := startCaptureTestFlow(t, b, 45002, false, dest, "control")
	captureWait(t, func() bool { return b.evidence.Snapshot(f.identity.PID).Counters.ReplyBytes >= 2 })
	if err := b.Reconfigure("selected", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	captureWait(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.flows[tuple] == nil })
	b.mu.Lock()
	oldGone := b.flows[tuple] == nil
	controlAlive := !control.retired
	b.mu.Unlock()
	if !oldGone || !controlAlive {
		t.Fatal("wrong UDP scope")
	}
	_, next := startCaptureTestFlow(t, b, 45001, false, dest, "selected")
	captureWait(t, func() bool {
		s := b.evidence.Snapshot(next.identity.PID)
		return len(s.Flows) == 1 && s.Flows[0].Counters.ReplyBytes > 0
	})
	if next.identity != f.identity {
		t.Fatal("process identity changed")
	}
	if b.evidence.Snapshot(next.identity.PID).Flows[0].Counters.DirectBytes != 0 {
		t.Fatal("required UDP leak")
	}
}

func TestNativeHotAttachDelegatedCloseDoesNotDeadlockOrKeepAlias(t *testing.T) {
	b, _ := captureFixture(t)
	redirect := &tcpRedirect{b: b, state: newTCPState(16), delegated: map[Tuple]delegatedTCP{}}
	id := ProcessIdentity{PID: 77, CreationTime: 12, Path: "chrome.exe"}
	owner := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	bound := owner
	bound.Source = netip.MustParseAddrPort("192.0.2.1:5678")
	b.evidence.BeginFlow(id, owner)
	b.evidence.RecordBytes(id, owner, "captured", "", 0)
	if !b.evidence.BindUpstream(id, bound, owner) {
		t.Fatal("bind failed")
	}
	left, right := net.Pipe()
	defer right.Close()
	c := &delegatedConn{Conn: left, release: func() { redirect.releaseDelegated(bound, id) }}
	done := make(chan struct{})
	go func() { redirect.state.mu.Lock(); defer redirect.state.mu.Unlock(); c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delegated close reentered TCP state lock")
	}
	b.evidence.RecordBytes(id, bound, "direct", "", 1)
	for _, f := range b.evidence.Snapshot(id.PID).Flows {
		if f.Source == owner.Source.String() && f.Counters.DirectBytes != 0 {
			t.Fatal("late native packet polluted owner", f)
		}
	}
}

func TestNativeHotAttachQuarantineNeverPassesOriginalPayload(t *testing.T) {
	b, _ := captureFixture(t)
	redirect := &tcpRedirect{b: b, port: 9999, state: newTCPState(16)}
	payload := []byte("existing TLS application bytes must not leave DIRECT")
	packet := localTCPPacket(24, payload)
	tuple, _, _, err := ParseTCP(packet)
	if err != nil {
		t.Fatal(err)
	}
	id := ProcessIdentity{PID: 77, CreationTime: 12, Path: "ChatGPT.exe"}
	d := Decision{Revision: "required", Flow: routing.Flow{ApplicationID: "openai"}, Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	writes := 0
	b.packetWriter = func(p []byte, a [80]byte) error {
		writes++
		_, flags, n, e := ParseTCP(p)
		if e != nil || flags != 4 || n != 0 || a[10]&2 != 0 {
			t.Error("original data/DIRECT egress escaped quarantine", e, flags, n)
		}
		return nil
	}
	var address [80]byte
	address[10] = 2
	redirect.quarantineNative(id, tuple, d, packet, address)
	redirect.processPacket(packet, address, func(ProcessIdentity, Tuple) Decision { return d })
	if writes != 2 {
		t.Fatal("no targeted local resets", writes)
	}
	flow := b.evidence.Snapshot(id.PID).Flows[0]
	if flow.Counters.DirectBytes != 0 || flow.Counters.Direct != 0 || flow.HotAttach == nil || flow.HotAttach.State != "HOT_ATTACH_PREEXISTING" || flow.FailureCause != "" {
		t.Fatal(flow)
	}
}

type delayedHotAbort struct {
	net.Conn
	entered, release chan struct{}
}

func (c *delayedHotAbort) Abort() error { close(c.entered); <-c.release; return c.Conn.Close() }
func TestNativeHotAttachDoesNotHoldGlobalPacketGateWhileDraining(t *testing.T) {
	b, _ := captureFixture(t)
	b.dll = &divertDLL{}
	b.tcp = &tcpRedirect{b: b, state: newTCPState(16)}
	left, right := net.Pipe()
	defer right.Close()
	slow := &delayedHotAbort{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	e := b.tcp.state.add(Tuple{}, ProcessIdentity{PID: 1}, Decision{Flow: routing.Flow{ApplicationID: "selected"}}, "relay", time.Now())
	e.upstream = slow
	done := make(chan error, 1)
	go func() { done <- b.Reconfigure("selected", func() error { return nil }) }()
	select {
	case <-slow.entered:
	case <-time.After(time.Second):
		t.Fatal("retirement did not start")
	}
	gate := make(chan struct{})
	go func() {
		b.policyMu.RLock()
		defer b.policyMu.RUnlock()
		if !b.hotFrozen(Decision{Flow: routing.Flow{ApplicationID: "selected"}}) || b.hotFrozen(Decision{Flow: routing.Flow{ApplicationID: "control"}}) {
			t.Error("wrong application fence")
		}
		close(gate)
	}()
	select {
	case <-gate:
	case <-time.After(time.Second):
		close(slow.release)
		t.Fatal("unrelated packet ingress stalled behind socket I/O")
	}
	if b.policyEpoch.Load() != 0 {
		t.Fatal("cache epoch published before policy commit")
	}
	close(slow.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("policy did not publish")
	}
	if b.policyEpoch.Load() != 1 {
		t.Fatal("policy cache did not advance on publication")
	}
}

func TestHotAttachIdentityChild(t *testing.T) {
	if os.Getenv("VELIQ_HOT_IDENTITY_CHILD") != "1" {
		t.Skip("owned identity fixture")
	}
	fmt.Println("IDENTITY_READY")
	io.Copy(io.Discard, os.Stdin)
}
func TestNativeHotAttachInvalidatesAlreadyRunningUnselectedUDPCache(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHotAttachIdentityChild$", "-test.v")
	cmd.Env = append(os.Environ(), "VELIQ_HOT_IDENTITY_CHILD=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	})
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "IDENTITY_READY" {
				close(ready)
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("owned helper identity unavailable")
	}
	id, err := NewDiscovery().Lookup(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := captureFixture(t)
	tuple := Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("192.0.2.1:48001"), Destination: netip.MustParseAddrPort("203.0.113.2:53")}
	b.flows[tuple] = &captureFlow{identity: id, done: make(chan struct{}), lastSeen: time.Now()}
	b.associations.Put(Association{Identity: id, Tuple: tuple})
	b.evidence.BeginFlow(id, tuple)
	b.evidence.RecordBytes(id, tuple, "direct", "", 100)
	b.policyEpoch.Store(1)
	raw := make([]byte, 29)
	raw[0] = 0x45
	raw[9] = 17
	binary.BigEndian.PutUint16(raw[2:], 29)
	copy(raw[12:16], []byte{192, 0, 2, 1})
	copy(raw[16:20], []byte{203, 0, 113, 2})
	binary.BigEndian.PutUint16(raw[20:], 48001)
	binary.BigEndian.PutUint16(raw[22:], 53)
	binary.BigEndian.PutUint16(raw[24:], 9)
	var a [80]byte
	a[10] = 2
	b.packetWriter = func(_ []byte, address [80]byte) error {
		if address[10]&2 != 0 {
			t.Error("obsolete native DIRECT cache leaked after profile activation")
		}
		return nil
	}
	d := Decision{Revision: "new-profile", Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true, Flow: routing.Flow{PID: id.PID, ProcessPath: id.Path, ApplicationID: "selected", Protocol: "udp", Source: tuple.Source, Destination: tuple.Destination, PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}}, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	b.processUDP(nil, raw, a, func(ProcessIdentity, Tuple) Decision { return d })
	captureWait(t, func() bool {
		s := b.evidence.Snapshot(id.PID)
		return len(s.Flows) == 1 && s.Flows[0].Counters.ReplyBytes == 1
	})
	f := b.evidence.Snapshot(id.PID).Flows[0]
	if f.Route != "RELAY" || f.Counters.DirectBytes != 0 || f.Counters.Direct != 0 || !IsCurrent(id) {
		t.Fatal(f)
	}
}

func TestNativeHotAttachBrowserPublicationPinsTCPRetiresOnlySelectedUDP(t *testing.T) {
	b, _ := captureFixture(t)
	b.dll = &divertDLL{}
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	tuple, selected := startCaptureTestFlow(t, b, 45101, false, dst, "selected")
	_, control := startCaptureTestFlow(t, b, 45102, false, dst, "control")
	captureWait(t, func() bool { return b.evidence.Snapshot(selected.identity.PID).Counters.ReplyBytes >= 2 })
	b.tcp = &tcpRedirect{b: b, state: newTCPState(16)}
	tcpTuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:51001"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	app, peer := net.Pipe()
	defer app.Close()
	defer peer.Close()
	upstream, origin := net.Pipe()
	defer upstream.Close()
	defer origin.Close()
	d := Decision{Flow: routing.Flow{ApplicationID: "selected"}}
	e := b.tcp.state.add(tcpTuple, ProcessIdentity{PID: 77, CreationTime: 1, Path: "chrome.exe"}, d, "relay", time.Now())
	e.local = app
	e.upstream = upstream
	epoch := b.policyEpoch.Load()
	hotEpoch := b.hot.snapshot().Epoch
	if err := b.ReconfigureNewConnections("selected", func() error {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !selected.retired || control.retired {
			return fmt.Errorf("wrong UDP fence scope")
		}
		if e.mode != "relay" || e.local != app || e.upstream != upstream {
			return fmt.Errorf("existing TCP touched before policy publication")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if b.policyEpoch.Load() != epoch+1 || b.hot.snapshot().Epoch != hotEpoch {
		t.Fatal("missing UDP epoch or scheduled TCP reconnect")
	}
	captureWait(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.flows[tuple] == nil })
	if e.mode != "relay" || e.local != app || e.upstream != upstream {
		t.Fatal("TCP moved/closed")
	}
	received := make(chan error, 1)
	go func() { var p [1]byte; _, err := io.ReadFull(peer, p[:]); received <- err }()
	app.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := app.Write([]byte("x")); err != nil {
		t.Fatal("existing TCP interrupted", err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	_, next := startCaptureTestFlow(t, b, 45101, false, dst, "selected")
	captureWait(t, func() bool { return b.evidence.Snapshot(next.identity.PID).Counters.ReplyBytes >= 2 })
	if b.evidence.Snapshot(next.identity.PID).Counters.DirectBytes != 0 {
		t.Fatal("selected UDP DIRECT leak")
	}
}
