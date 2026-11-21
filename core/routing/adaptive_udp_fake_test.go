package routing

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAdaptiveUDPFakePreludeOnlyBeforeFirstDirectDatagrams(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	e := New(8)
	f := Flow{Protocol: "udp", PID: 1, ProcessPath: "Discord.exe", ApplicationID: "discord", Source: netip.MustParseAddrPort("127.0.0.1:1201"), Destination: netip.MustParseAddrPort(server.LocalAddr().String()), UDPFakePrelude: 6, UDPFakeCutoff: 2}
	d, err := e.OpenAdaptiveUDP(context.Background(), f, "offline", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, m := range []string{"a", "b", "c"} {
		if err = d.Send([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	buf := make([]byte, 2048)
	for len(got) < 15 {
		server.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("after %d datagrams: %v", len(got), err)
		}
		if n == 64 && bytes.Equal(buf[:n], make([]byte, 64)) {
			got = append(got, "fake")
		} else {
			got = append(got, string(buf[:n]))
		}
	}
	want := []string{"fake", "fake", "fake", "fake", "fake", "fake", "a", "fake", "fake", "fake", "fake", "fake", "fake", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("datagram order %v", got)
		}
	}
	if h := d.Health(); h.FakePrelude != 12 {
		t.Fatalf("evidence %+v", h)
	}
}

func TestAdaptiveUDPWithoutPreludeSendsNoFakes(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	e := New(8)
	f := Flow{Protocol: "udp", PID: 1, ProcessPath: "game.exe", ApplicationID: "game", Source: netip.MustParseAddrPort("127.0.0.1:1202"), Destination: netip.MustParseAddrPort(server.LocalAddr().String())}
	d, err := e.OpenAdaptiveUDP(context.Background(), f, "offline", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.Send([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := server.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "x" {
		t.Fatalf("first datagram %q %v", buf[:n], err)
	}
}

func TestLenientProbationConfirmsQuietDiscordVoiceOnly(t *testing.T) {
	start := time.Now()
	run := func(lenient uint64, replies int) (bool, string) {
		h := udpCadence{lenientReplies: lenient}
		h.observe(start, false, 74)
		for i := 0; i < replies; i++ {
			h.observe(start.Add(time.Duration(100*(i+1))*time.Millisecond), true, 74)
		}
		return h.check(start.Add(3*time.Second), 3*time.Second)
	}
	if ok, failure := run(2, 2); !ok || failure != "" {
		t.Fatalf("lenient 2 replies: %v %q", ok, failure)
	}
	if ok, failure := run(2, 1); ok || failure != DirectInsufficientReplies {
		t.Fatalf("lenient 1 reply must fall back: %v %q", ok, failure)
	}
	if ok, failure := run(0, 2); ok || failure != DirectInsufficientReplies {
		t.Fatalf("default probation unchanged: %v %q", ok, failure)
	}
}
