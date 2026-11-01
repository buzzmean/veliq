package clientservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestBrowserDNSRecoveryScopeChangeDropsReplyAndHints(t *testing.T) {
	for _, kind := range []string{"network", "off", "profile", "revision", "pid", "birth", "path", "routing-disabled", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			c, cur := timeoutFixture(t)
			query, reply := brokerWire(t, "chatgpt.com")
			tuple := policyTuple("udp", 53)
			after := cur
			revision := "original"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				out, e := c.exchangeBrowserDNSChecked(ctx, cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
					close(entered)
					<-release
					return reply, nil
				}, func() error {
					if !browserDNSSameScope(cur, after, "original", revision) {
						return errors.New("scope changed")
					}
					return nil
				})
				if len(out) > 0 {
					done <- errors.New("stale answer delivered")
				} else {
					done <- e
				}
			}()
			<-entered
			switch kind {
			case "network":
				after.network = "other"
			case "off":
				after.enabled = false
			case "profile":
				after.profile.ID = "other"
			case "revision":
				revision = "changed"
			case "pid":
				after.id.PID++
			case "birth":
				after.id.CreationTime++
			case "path":
				after.id.Path = "other.exe"
			case "routing-disabled":
				after.routingDisabled = true
			case "cancel":
				cancel()
			}
			close(release)
			if e := <-done; e == nil {
				t.Fatal("late DNS result accepted", kind)
			}
			if len(c.browser.domains.owned) != 0 {
				t.Fatal("stale DNS hints published")
			}
			rows := c.browser.dnsWire.snapshot()["records"].([]browserDNSRecord)
			want := "DNS_SCOPE_CHANGED"
			if kind == "cancel" {
				want = "DNS_CANCELED"
			}
			if len(rows) != 1 || rows[0].Result != want || rows[0].Diagnosis.State != want {
				t.Fatal(rows)
			}
		})
	}
}
func TestBrowserDNSRecoveryReplyFeedsExistingPlannerAndTTL(t *testing.T) {
	for _, host := range []string{"chatgpt.com", "web.telegram.org", "claude.ai"} {
		c, cur := timeoutFixture(t)
		query, reply := brokerWire(t, host)
		cur.profile.Executables = []string{`C:\Apps\chrome.exe`}
		for _, proto := range []string{"udp", "tcp"} {
			tuple := policyTuple(proto, 53)
			out, e := c.exchangeBrowserDNS(context.Background(), cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) { return reply, nil })
			if e != nil || !bytes.Equal(out, reply) {
				t.Fatal(host, e)
			}
			ip := netip.MustParseAddr("87.240.137.208")
			evidence := c.browser.domains.profileEvidence(cur.network, cur.profile.ID, ip, "", time.Now())
			target := policyTuple("tcp", 443)
			target.Destination = netip.AddrPortFrom(ip, 443)
			plan := c.nativeOpaquePlan(cur.profile, target, cur.network, evidence)
			if evidence.Domain != host || plan.Destination != target.Destination || plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
				t.Fatal("recovered protected name lost route floor", host, evidence, plan)
			}
			if e := c.browser.domains.profileEvidence(cur.network, cur.profile.ID, ip, "", time.Now().Add(11*time.Second)); len(e.Candidates) != 0 {
				t.Fatal("wire TTL extended", e)
			}
			if e := c.browser.domains.profileEvidence("other", cur.profile.ID, ip, "", time.Now()); len(e.Candidates) != 0 {
				t.Fatal("hint escaped network", e)
			}
		}
	}
}
func TestBrowserDNSRecoveryOrdinaryNegativeNeverUsesRelay(t *testing.T) {
	for _, host := range []string{"vk.ru", "yandex.ru"} {
		c, cur := timeoutFixture(t)
		query, _ := brokerWire(t, host)
		reply := browserproxy.DNSFailure(query)
		server, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer server.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 8192)
			_, peer, e := server.ReadFrom(buf)
			if e == nil {
				server.WriteTo(reply, peer)
			}
		}()
		tuple := policyTuple("udp", 53)
		tuple.Destination = server.LocalAddr().(*net.UDPAddr).AddrPort()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		out, e := c.exchangeBrowserDNS(ctx, cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
			t.Error("ordinary failure sent to VPS")
			return nil, errors.New("forbidden")
		})
		cancel()
		<-done
		if e != nil || !bytes.Equal(out, reply) {
			t.Fatal("ordinary failure semantics changed", e)
		}
		if _, e := c.browserDNSRelayWire(context.Background(), cur, tuple, query); e == nil {
			t.Fatal("recovery caller bypassed name policy")
		}
	}
}
func TestBrowserDNSRecoveryCapacityAndCanceledAdmission(t *testing.T) {
	c, cur := timeoutFixture(t)
	query, reply := brokerWire(t, "www.youtube.com")
	tuple := policyTuple("udp", 53)
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var calls atomic.Int32
	relay := func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return reply, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := c.exchangeBrowserDNS(context.Background(), cur, tuple, query, relay)
			if e != nil {
				t.Error(e)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		<-entered
	}
	if _, e := c.exchangeBrowserDNS(context.Background(), cur, tuple, query, relay); e == nil || e.Error() != "BROWSER_DNS_CAPACITY" {
		t.Fatal("unbounded DNS admission", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.exchangeBrowserDNS(ctx, cur, tuple, query, relay); e == nil {
		t.Fatal("canceled query admitted")
	}
	if calls.Load() != 16 {
		t.Fatal("extra relay opens", calls.Load())
	}
	once.Do(func() { close(release) })
	wg.Wait()
	if len(c.browser.dnsWire.slots) != 0 {
		t.Fatal("DNS slot leak")
	}
}
func TestBrowserDNSRecoveryTCPStreamReturnsRecoveredAnswer(t *testing.T) {
	c, cur := timeoutFixture(t)
	query, reply := brokerWire(t, "www.youtube.com")
	tuple := policyTuple("tcp", 53)
	conn := browserproxy.NewDNSStream(context.Background(), func(ctx context.Context, wire []byte) ([]byte, error) {
		return c.exchangeBrowserDNS(ctx, cur, tuple, wire, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) { return reply, nil })
	})
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() {
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(query)))
		_, e := conn.Write(append(prefix[:], query...))
		done <- e
	}()
	var prefix [2]byte
	if _, e := io.ReadFull(conn, prefix[:]); e != nil {
		t.Fatal(e)
	}
	answer := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, e := io.ReadFull(conn, answer); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil || !bytes.Equal(answer, reply) {
		t.Fatal(e)
	}
}
