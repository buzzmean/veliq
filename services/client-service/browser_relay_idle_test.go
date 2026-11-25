package clientservice

import (
	"github.com/buzzmean/veliq/core/browserproxy"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRelayIdlePreconnectExpiresAndFreesOnlyOwnPermit(t *testing.T) {
	u := &browserRelayUsage{}
	r, ok := u.acquireVideo()
	if !ok {
		t.Fatal("permit")
	}
	a, b := net.Pipe()
	defer b.Close()
	c := &relayMeterConn{Conn: a, usage: u, release: r}
	defer c.Close()
	c.armIdle(25*time.Millisecond, time.Second, false)
	deadline := time.Now().Add(time.Second)
	for u.snapshot().VideoActive > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	c.Close()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("idle reclaim mislabeled as upstream/session failure", err)
	}
	if s := u.snapshot(); s.VideoActive != 0 || s.VideoIdleClosed != 1 {
		t.Fatal(s)
	}
}
func TestRelaySuccessfulIOInvalidatesOldIdleTimerAndKeepsActiveFlow(t *testing.T) {
	u := &browserRelayUsage{}
	r, _ := u.acquireVideo()
	a, b := net.Pipe()
	defer b.Close()
	c := &relayMeterConn{Conn: a, usage: u, release: r}
	defer c.Close()
	c.armIdle(time.Second, 50*time.Millisecond, false)
	// Deterministically invoke a stale callback after successful I/O re-armed it.
	c.mu.Lock()
	oldGeneration := c.generation
	c.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, e := io.ReadFull(b, make([]byte, 8)); done <- e }()
	if _, e := c.Write([]byte("data")); e != nil {
		t.Fatal(e)
	}
	c.expireIdle(oldGeneration)
	if u.snapshot().VideoActive != 1 {
		t.Fatal("stale callback closed active stream")
	}
	if _, e := c.Write([]byte("more")); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for u.snapshot().VideoActive > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s := u.snapshot(); s.VideoIdleClosed != 1 || s.VideoActive != 0 || len(s.Minutes) != 1 || s.Minutes[0].Sent != 8 {
		t.Fatal(s)
	}
}

func TestPlayerParallelRangesAndSeekWaitWhileOpaquePoolIsFull(t *testing.T) {
	u := &browserRelayUsage{}
	var opaque []func()
	for i := 0; i < opaqueGoogleRelayLimit; i++ {
		r, ok := u.acquireVideoContext(t.Context(), true)
		if !ok {
			t.Fatal("opaque setup")
		}
		opaque = append(opaque, r)
	}
	gate := make(chan struct{})
	admitted := make(chan struct{}, 16)
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			release, ok := u.acquireVideoContext(t.Context())
			if !ok {
				done <- io.ErrNoProgress
				return
			}
			defer release()
			admitted <- struct{}{}
			<-gate
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			copied := make(chan error, 1)
			go func() { _, e := b.Write([]byte("segment")); copied <- e }()
			var payload [7]byte
			_, e := io.ReadFull(a, payload[:])
			if e == nil {
				e = <-copied
			}
			done <- e
		}()
	}
	for i := 0; i < videoRelayLimit; i++ {
		select {
		case <-admitted:
		case <-time.After(time.Second):
			close(gate)
			t.Fatal("video starved by opaque")
		}
	}
	deadline := time.Now().Add(time.Second)
	for u.snapshot().VideoWaiting < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s := u.snapshot()
	close(gate)
	if s.VideoActive != 12 || s.OpaqueGoogleActive != 4 || s.VideoWaiting != 4 {
		t.Fatal(s)
	}
	for i := 0; i < 16; i++ {
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("queued segment stuck")
		}
	}
	for _, release := range opaque {
		release()
	}
	deadline = time.Now().Add(time.Second)
	for u.snapshot().TotalGoogleActive > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s = u.snapshot(); s.TotalGoogleActive != 0 || s.VideoTimeouts != 0 || s.VideoWaited != 4 {
		t.Fatal(s)
	}
}

func TestGoogleWebAdmissionExcludesPushPortsAndKnownProtectedControl(t *testing.T) {
	for _, port := range []uint16{80, 443, 5228} {
		q := browserproxy.Request{Host: "mtalk.google.com", Port: port}
		p := browserproxy.Plan{Destination: netip.AddrPortFrom(netip.MustParseAddr("64.233.162.188"), port)}
		if got := otherGoogleWebAdmission(q, p); got != (port == 443) {
			t.Fatal(port, got)
		}
	}
	for _, host := range []string{"rr1.googlevideo.com", "youtubei.googleapis.com", "yt3.ggpht.com"} {
		if otherGoogleWebAdmission(browserproxy.Request{Host: host, Port: 443}, browserproxy.Plan{Destination: netip.MustParseAddrPort("64.233.162.188:443")}) {
			t.Fatal("protected control competes with opaque", host)
		}
	}
}
