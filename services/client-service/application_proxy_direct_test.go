package clientservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDirectGameProxyPlanningDoesNotDependOnBrowserDNS(t *testing.T) {
	for _, image := range []string{`C:\Steam\steam.exe`, `C:\Steam\game\bin\cs2.exe`, `C:\Games\Other\game.exe`} {
		t.Run(image, func(t *testing.T) {
			p := profiles.Profile{ID: "game-login-direct", Name: "Game login", Executables: []string{image}, Mode: profiles.Direct, Custom: true}
			c := policyController(t, p)
			id := wp.ProcessIdentity{PID: 31, CreationTime: 123, Path: image}
			var calls atomic.Int32
			c.BrowserResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("isolated browser DNS unavailable")
			}}
			q := browserproxy.Request{Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, Source: netip.MustParseAddrPort("127.0.0.1:55123"), Host: "login.game.invalid", Port: 443}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			plan, err := c.authorityPlanForOwner(ctx, id, q)
			if err != nil || calls.Load() != 0 || plan.Enabled || plan.Policy.Action != flowpolicy.Direct || plan.BrowserRecoveryAuthorized {
				t.Fatalf("DIRECT login depends on browser DNS: calls=%d plan=%+v err=%v", calls.Load(), plan, err)
			}
		})
	}
}

func directProxyFixture(t *testing.T) (*Controller, wp.ProcessIdentity, profiles.Profile, browserproxy.Request) {
	t.Helper()
	p := profiles.Profile{ID: "game-login-direct", Name: "Game login", Executables: []string{`C:\Steam\steam.exe`}, Mode: profiles.Direct}
	c := policyController(t, p)
	id := wp.ProcessIdentity{PID: 31, CreationTime: 123, Path: p.Executables[0]}
	q := browserproxy.Request{Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, Source: netip.MustParseAddrPort("127.0.0.1:55123"), Host: "localhost"}
	return c, id, p, q
}

func TestDirectGameProxyRealServerFirstAndOriginalBytes(t *testing.T) {
	c, id, _, q := directProxyFixture(t)
	preferGameRelay(c)
	relay := &unwantedGameRelay{}
	c.Engine.SetRelay("VPS-01", relay)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	q.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	payload := []byte{0, 1, 0, 8, 255, 4, 3, 0}
	result := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := peer.Write([]byte("game-login-ready")); err != nil {
			result <- err
			return
		}
		body := make([]byte, len(payload))
		_, err = io.ReadFull(peer, body)
		if err == nil && string(body) != string(payload) {
			err = errors.New("game bytes changed")
		}
		if err == nil {
			_, err = peer.Write(body)
		}
		result <- err
	}()
	dialer := c.applicationProxyDirectDialer(q, func() (wp.ProcessIdentity, error) { return id, nil })
	if dialer.Resolver != nil {
		t.Fatal("DIRECT replaced OS resolver")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(q.Host, strconv.Itoa(int(q.Port))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	banner := make([]byte, len("game-login-ready"))
	if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "game-login-ready" {
		t.Fatal("server-first protocol stalled", string(banner), err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || string(body) != string(payload) {
		t.Fatal("game exchange changed or replayed", body, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if relay.calls.Load() != 0 || len(c.Engine.Snapshot()) != 0 {
		t.Fatal("DIRECT login entered relay routing")
	}
}

func proxyAddressResolver(t *testing.T, addresses ...[4]byte) *net.Resolver {
	t.Helper()
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			var question dnsmessage.Message
			if question.Unpack(buffer[:n]) != nil || len(question.Questions) != 1 {
				continue
			}
			q := question.Questions[0]
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: question.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: question.Questions}
			if q.Type == dnsmessage.TypeA {
				for _, address := range addresses {
					answer.Answers = append(answer.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: address}})
				}
			}
			if raw, err := answer.Pack(); err == nil {
				_, _ = dns.WriteTo(raw, peer)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", dns.LocalAddr().String())
	}}
}

func TestDirectGameProxyTriesNextResolvedAddressBeforeAnyGameBytes(t *testing.T) {
	c, id, _, q := directProxyFixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	q.Host, q.Port = "login.game.invalid", uint16(listener.Addr().(*net.TCPAddr).Port)
	dialer := c.applicationProxyDirectDialer(q, func() (wp.ProcessIdentity, error) { return id, nil })
	// Only this isolated test substitutes DNS; production leaves Resolver nil.
	dialer.Resolver = proxyAddressResolver(t, [4]byte{127, 0, 0, 2}, [4]byte{127, 0, 0, 1})
	var attempts []string
	control := dialer.Control
	dialer.Control = func(network, address string, raw syscall.RawConn) error {
		attempts = append(attempts, address)
		return control(network, address, raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(q.Host, strconv.Itoa(int(q.Port))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if len(attempts) != 2 || !strings.HasPrefix(attempts[0], "127.0.0.2:") || conn.RemoteAddr().String() != listener.Addr().String() {
		t.Fatal("healthy alternate address not selected", attempts, conn.RemoteAddr())
	}
}

func TestDirectGameProxyRejectsChangedOwnerOrPolicyBeforeSYN(t *testing.T) {
	for _, change := range []string{"owner", "profile", "rules", "deleted"} {
		t.Run(change, func(t *testing.T) {
			c, id, p, q := directProxyFixture(t)
			q.Host, q.Port = "127.0.0.1", 443
			dialer := c.applicationProxyDirectDialer(q, func() (wp.ProcessIdentity, error) {
				switch change {
				case "owner":
					return wp.ProcessIdentity{}, browserproxy.ErrOwnerLookup
				case "profile":
					p.Mode = profiles.Block
					_ = c.Profiles.Upsert(p)
				case "rules":
					p.Rules = []flowpolicy.Rule{{ID: "deny", Action: flowpolicy.Block}}
					if err := c.Profiles.Upsert(p); err != nil {
						t.Fatal(err)
					}
				case "deleted":
					c.Profiles.Delete(p.ID)
				}
				return id, nil
			})
			if err := dialer.Control("tcp4", "127.0.0.1:443", nil); err == nil {
				t.Fatal("stale owner or profile authorized SYN")
			}
		})
	}
}

func TestDirectGameProxyRetainsProtectedAndExplicitPolicies(t *testing.T) {
	c, id, p, q := directProxyFixture(t)
	for _, host := range []string{"chatgpt.com", "api.openai.com"} {
		q.Host, q.Port = host, 443
		plan, ok := c.applicationProxyDirectPlan(id, q)
		if !ok || plan.Policy.Action != flowpolicy.Block {
			t.Fatal("protected origin escaped DIRECT", host, plan)
		}
		dialer := c.applicationProxyDirectDialer(q, func() (wp.ProcessIdentity, error) { return id, nil })
		if err := dialer.Control("tcp4", "203.0.113.10:443", nil); err == nil {
			t.Fatal("protected authority authorized SYN")
		}
	}
	q.Host = "ordinary.game.invalid"
	c.network.Store(&wp.NetworkContext{Fingerprint: strings.Repeat("a", 64), ObservedAt: time.Now()})
	c.browser.domains.replace(strings.Repeat("a", 64), []wp.DNSCacheEntry{{Name: "chatgpt.com", Address: "203.0.113.10", TTL: 60}}, nil, time.Now())
	dialer := c.applicationProxyDirectDialer(q, func() (wp.ProcessIdentity, error) { return id, nil })
	if err := dialer.Control("tcp4", "203.0.113.10:443", nil); err == nil {
		t.Fatal("resolved protected address escaped guard")
	}
	for _, mode := range []profiles.Mode{profiles.Auto, profiles.Manual, profiles.Block, profiles.DirectPlus} {
		p.Mode, p.RelayID = mode, "VPS-01"
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
		if _, ok := c.applicationProxyDirectPlan(id, q); ok {
			t.Fatal("non-DIRECT policy overridden", mode)
		}
	}
	p.Mode, p.RelayID, p.Fallback = profiles.Direct, "", flowpolicy.Required
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.applicationProxyDirectPlan(id, q); ok {
		t.Fatal("required fallback bypassed")
	}
}
