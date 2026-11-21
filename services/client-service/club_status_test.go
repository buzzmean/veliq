package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/internal/e2eprobe"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClubSelfcheckNoFalsePageOrGamePass(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.clubMode.Store(true)
	s := c.clubStatus()
	if s.State != "PENDING" || s.PageResult != "NOT_VERIFIED" || s.GameResult != "NOT_VERIFIED" {
		t.Fatalf("false PASS: %+v", s)
	}
	file := filepath.Join(t.TempDir(), "club-status.json")
	if err := writeClubStatus(file, "S-1-5-21-1-2-3-1001", s); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	var check ClubStatus
	if json.Unmarshal(raw, &check) != nil || check.State != "PENDING" {
		t.Fatal("invalid status")
	}
	for _, secret := range []string{"machine_hash", "hardware_salt", "request_id", "ipc.token", "private_key", "activation_code"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private field in summary", secret)
		}
	}
}

type clubEchoDatagram struct {
	key, raw []byte
	closed   bool
}

func (d *clubEchoDatagram) Send(b []byte) error {
	p, e := e2eprobe.Decode(b, d.key)
	if e != nil {
		return e
	}
	p.Reply = true
	p.Peer = netip.MustParseAddrPort("198.51.100.1:1234")
	d.raw = e2eprobe.Encode(p, d.key)
	return nil
}
func (d *clubEchoDatagram) Receive(context.Context) ([]byte, error) { return d.raw, nil }
func (d *clubEchoDatagram) Close() error                            { d.closed = true; return nil }
func TestClubSelfcheckActualAuthenticatedTCPUDPAndNonceBinding(t *testing.T) {
	key := []byte("fixture-only-not-a-production-echo-key")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dst := netip.MustParseAddrPort("198.51.100.1:40000")
	d := &clubEchoDatagram{key: key}
	if got := clubUDPProof(ctx, func(context.Context, netip.AddrPort) (routing.Datagram, error) { return d, nil }, dst, key); got != "PASS" || !d.closed {
		t.Fatal("UDP exchange failed", got)
	}
	opener := func(context.Context, netip.AddrPort) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			raw := make([]byte, e2eprobe.Size)
			io.ReadFull(b, raw)
			p, e := e2eprobe.Decode(raw, key)
			if e != nil {
				return
			}
			p.Reply = true
			p.Peer = dst
			b.Write(e2eprobe.Encode(p, key))
		}()
		return a, nil
	}
	if got := clubTCPProof(ctx, opener, dst, key); got != "PASS" {
		t.Fatal("TCP exchange failed", got)
	}
	p := e2eprobe.Packet{Sequence: 1, Reply: true, Peer: dst}
	q := p
	q.Run[0] = 1
	if clubValidateEcho(e2eprobe.Encode(p, key), key, q) == "PASS" || clubValidateEcho([]byte("unauthenticated"), key, p) == "PASS" {
		t.Fatal("invalid reply accepted")
	}
}
