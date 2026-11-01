//go:build windows

package clientservice

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

// Проверяет настоящий Windows PID/birth/SID на отдельном тестовом процессе.
// Это не настоящий Chrome и не доказательство browser/ISP acceptance.
func TestBrowserDNSRecoveryWindowsOwnerAndOffNoDirect(t *testing.T) {
	if os.Getenv("VELIQ_DNS_OWNER_FIXTURE") == "1" {
		io.Copy(io.Discard, os.Stdin)
		return
	}
	source, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	helper := filepath.Join(t.TempDir(), "chrome.exe")
	if e = os.WriteFile(helper, data, 0700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(helper, "-test.run=^TestBrowserDNSRecoveryWindowsOwnerAndOffNoDirect$")
	cmd.Env = append(os.Environ(), "VELIQ_DNS_OWNER_FIXTURE=1")
	input, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	waited := false
	t.Cleanup(func() {
		input.Close()
		if !waited {
			cmd.Wait()
		}
	})
	id, e := wp.NewDiscovery().Lookup(uint32(cmd.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	sid, e := wp.ProcessUserSID(id)
	if e != nil {
		t.Fatal(e)
	}
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = sid
	c.mu.Lock()
	c.enabled = true
	c.settings.Automatic = true
	c.mu.Unlock()
	c.network.Store(&wp.NetworkContext{Fingerprint: "isolated", ObservedAt: time.Now()})
	p := dnsRecoveryOwnerProfile(helper)
	if e = c.Profiles.Upsert(p); e != nil {
		t.Fatal("invalid owner fixture profile", e)
	}
	owner := browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}
	cur, e := c.browserProfile(owner)
	if e != nil {
		t.Fatal(e)
	}
	tuple := policyTuple("udp", 53)
	tuple.Destination = netip.MustParseAddrPort("127.0.0.1:9")
	decision := c.browserDNSDecision(p, id, tuple, wp.Decision{}, cur.network)
	check := c.browserDNSScopeCheck(cur)
	if e = check(); e != nil {
		t.Fatal("current Windows owner rejected", e)
	}
	c.BrowserOwnerSID = "S-1-5-18"
	if sid == c.BrowserOwnerSID {
		c.BrowserOwnerSID = "S-1-5-19"
	}
	if e = check(); e == nil {
		t.Fatal("wrong owner SID accepted")
	}
	c.BrowserOwnerSID = sid
	reused := cur
	reused.id.CreationTime++
	if e = c.browserDNSScopeCheck(reused)(); e == nil {
		t.Fatal("reused PID accepted")
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "new-network", ObservedAt: time.Now()})
	if e = check(); e == nil {
		t.Fatal("old network accepted")
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: cur.network, ObservedAt: time.Now()})
	c.mu.Lock()
	c.enabled = false
	c.mu.Unlock()
	if e = check(); e == nil {
		t.Fatal("OFF accepted old result")
	}
	query, _ := brokerWire(t, "chatgpt.com")
	if _, e = decision.DNSExchange(context.Background(), query); e == nil || c.browser.dnsWire.queries != 0 {
		t.Fatal("OFF before worker start reached DNS transaction", e)
	}
	// Cached PAC может делать DIRECT при OFF, но DNS recovery — никогда.
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	dst := listener.Addr().(*net.TCPAddr).AddrPort()
	plan := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: dst, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required, Source: "browser_dns_wire_doh"}}
	conn, e := c.browserOpenUnobserved(context.Background(), browserproxy.Request{Owner: owner, Port: 443, Secure: true}, plan)
	if conn != nil {
		conn.Close()
		t.Fatal("DNS recovery escaped to DIRECT")
	}
	if e == nil || e.Error() != "BROWSER_DNS_SCOPE_CHANGED" {
		t.Fatal("wrong DNS stop boundary", e)
	}
	input.Close()
	e = cmd.Wait()
	waited = true
	if e != nil {
		t.Fatal(e)
	}
	if e = check(); e == nil {
		t.Fatal("exited process accepted")
	}
}
