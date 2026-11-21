package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/quic-go/quic-go"
)

// A bounded UDP delay bridge without intentional packet drops: packets are scheduled independently,
// not serialized by one sleep per packet. It exercises real encrypted QUIC and
// the real relay TCP copy loop; no Internet/WinDivert/player performance claim.
func delayedRelay(t *testing.T, target string, delay time.Duration) string {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	a, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp4", nil, a)
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	// Bridge socket buffers are deliberately larger than a congestion burst.
	// These are lab sockets only; production socket settings are unchanged.
	for _, c := range []*net.UDPConn{front, back} {
		if e := c.SetReadBuffer(4 * 1024 * 1024); e != nil {
			t.Fatal(e)
		}
		if e := c.SetWriteBuffer(4 * 1024 * 1024); e != nil {
			t.Fatal(e)
		}
	}
	type packet struct {
		b  []byte
		a  *net.UDPAddr
		at time.Time
	}
	up, down := make(chan packet, 4096), make(chan packet, 4096)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var owner *net.UDPAddr
	enqueue := func(ch chan packet, p packet) bool {
		select {
		case ch <- p:
			return true
		case <-stop:
			return false
		}
	}
	wg.Add(4)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, a, e := front.ReadFromUDP(buf)
			if e != nil {
				return
			}
			mu.Lock()
			owner = a
			mu.Unlock()
			if !enqueue(up, packet{bytes.Clone(buf[:n]), nil, time.Now().Add(delay)}) {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, e := back.Read(buf)
			if e != nil {
				return
			}
			mu.Lock()
			a := owner
			mu.Unlock()
			if !enqueue(down, packet{bytes.Clone(buf[:n]), a, time.Now().Add(delay)}) {
				return
			}
		}
	}()
	for _, leg := range []struct {
		q        chan packet
		outbound bool
	}{{up, true}, {down, false}} {
		go func(q chan packet, outbound bool) {
			defer wg.Done()
			var next time.Time
			for {
				select {
				case <-stop:
					return
				case p := <-q:
					// 100 Mbit/s per direction, bounded queue, no intentional loss.
					if next.After(p.at) {
						p.at = next
					}
					next = p.at.Add(time.Duration(len(p.b)) * 8 * time.Second / 100000000)
					timer := time.NewTimer(time.Until(p.at))
					select {
					case <-stop:
						timer.Stop()
						return
					case <-timer.C:
					}
					var writeErr error
					if outbound {
						_, writeErr = back.Write(p.b)
					} else if p.a != nil {
						_, writeErr = front.WriteToUDP(p.b, p.a)
					}
					if writeErr != nil {
						return
					}
				}
			}
		}(leg.q, leg.outbound)
	}
	t.Cleanup(func() { close(stop); front.Close(); back.Close(); wg.Wait() })
	return front.LocalAddr().String()
}

func TestRelayBulkReceiveWindowsAt60msRTT(t *testing.T) {
	// No threshold on throughput: race/loaded CI are not reliable speed meters.
	// Exact payload, concurrent streams, and same QUIC session are strict checks.
	payload := bytes.Repeat([]byte("video-range-integrity"), 400000)
	want := sha256.Sum256(payload)
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var originWG sync.WaitGroup
	defer originWG.Wait()
	defer origin.Close()
	originWG.Add(1)
	go func() {
		defer originWG.Done()
		for {
			c, e := origin.Accept()
			if e != nil {
				return
			}
			originWG.Add(1)
			go func() {
				defer originWG.Done()
				defer c.Close()
				var request [1]byte
				if _, e := io.ReadFull(c, request[:]); e == nil {
					c.Write(payload)
				}
			}()
		}
	}()
	// Direct loopback is an integrity/overhead reference, not a WAN baseline.
	direct, e := net.DialTimeout("tcp4", origin.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	direct.SetDeadline(time.Now().Add(10 * time.Second))
	started := time.Now()
	if _, e = direct.Write([]byte{1}); e != nil {
		direct.Close()
		t.Fatal(e)
	}
	h := sha256.New()
	n, e := io.Copy(h, direct)
	direct.Close()
	if e != nil || n != int64(len(payload)) || !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("direct bulk mismatch", n, e)
	}
	t.Logf("direct LOOPBACK (no WAN delay) Mbps=%.2f", float64(n)*8/time.Since(started).Seconds()/1e6)

	for _, mode := range []string{"legacy", "client_download"} {
		t.Run(mode, func(t *testing.T) {
			r, _, tls := setup(t, 30*time.Second)
			addr := delayedRelay(t, r.Addr().String(), 30*time.Millisecond)
			cfg := transport.QUICConfig()
			if mode == "client_download" {
				cfg = transport.ClientQUICConfig()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			start := time.Now()
			conn, e := quic.DialAddr(ctx, addr, tls, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.CloseWithError(0, "done")
			t.Logf("cold mTLS session=%s", time.Since(start))
			for _, count := range []int{1, 4} {
				type result struct {
					open, first, total time.Duration
					err                error
					bytes              int64
				}
				results := make(chan result, count)
				start := time.Now()
				for i := 0; i < count; i++ {
					go func(id int) {
						started := time.Now()
						s, e := conn.OpenStreamSync(ctx)
						if e != nil {
							results <- result{err: e}
							return
						}
						s.SetDeadline(time.Now().Add(25 * time.Second))
						e = (protocol.Open{Kind: protocol.TCP, ID: uint32(count*10 + id), Destination: netip.MustParseAddrPort(origin.Addr().String())}).Write(s)
						var ack [1]byte
						if e == nil {
							_, e = io.ReadFull(s, ack[:])
							if e == nil && ack[0] != 0 {
								e = io.ErrUnexpectedEOF
							}
						}
						v := result{open: time.Since(started), err: e}
						if e != nil {
							results <- v
							return
						}
						_, e = s.Write([]byte{1})
						if e != nil {
							v.err = e
							results <- v
							return
						}
						s.Close()
						var first [1]byte
						_, e = io.ReadFull(s, first[:])
						v.first = time.Since(started)
						h := sha256.New()
						if e == nil {
							h.Write(first[:])
							v.bytes, e = io.Copy(h, s)
							v.bytes++
						}
						v.total = time.Since(started)
						if e == nil && (v.bytes != int64(len(payload)) || !bytes.Equal(h.Sum(nil), want[:])) {
							e = io.ErrUnexpectedEOF
						}
						v.err = e
						results <- v
					}(i)
				}
				for i := 0; i < count; i++ {
					v := <-results
					if v.err != nil {
						t.Fatal(v.err)
					}
					t.Logf("streams=%d open=%s first=%s total=%s Mbps=%.2f", count, v.open, v.first, v.total, float64(v.bytes)*8/v.total.Seconds()/1e6)
				}
				t.Logf("aggregate streams=%d Mbps=%.2f", count, float64(count*len(payload))*8/time.Since(start).Seconds()/1e6)
			}
		})
	}
}

func TestPoolBulkReusesAuthenticatedSessionAndMeasuresOpenPhases(t *testing.T) {
	x := newPoolFixture(t, transport.DefaultPoolConfig(), nil)
	data := bytes.Repeat([]byte("same-authenticated-stream-integrity"), 32768)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := x.pool.OpenTCP(ctx, x.tcp)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		done := make(chan error, 1)
		go func() {
			_, e := c.Write(data)
			if e == nil {
				e = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- e
		}()
		got, e := io.ReadAll(c)
		if e != nil || !bytes.Equal(got, data) {
			t.Fatal("bulk echo differs", len(got), e)
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		c.Close()
	}
	s := x.pool.Snapshot()
	if s.ActiveSessions != 1 || s.OpenCount != 2 || s.ActiveFlows != 0 || x.issued.Load() != 1 {
		t.Fatal("session/ticket reuse or flow release broken", s, x.issued.Load())
	}
	if len(s.RecentOpens) != 2 || s.RecentOpens[0].SessionID != s.RecentOpens[1].SessionID {
		t.Fatal("QUIC session replaced")
	}
	// Loopback stream open can fall inside the Windows monotonic clock tick and
	// read as exactly 0 ms; negative or inconsistent phases remain failures.
	for _, v := range s.RecentOpens {
		if v.AcquireMS < 0 || v.StreamOpenMS < 0 || v.SessionAgeMS < 0 || v.DurationMS+0.001 < v.AcquireMS+v.StreamOpenMS || v.FailureReason != "" {
			t.Fatalf("phase timing invalid: %+v", v)
		}
	}
	t.Log("two complete TCP payloads; same mTLS/fresh-ticket session reused; no application replay/socket replacement")
}
