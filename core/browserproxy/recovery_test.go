package browserproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func recoveryEcho(t *testing.T) (string, func(context.Context, Request) (net.Conn, error)) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l.Addr().String(), func(ctx context.Context, _ Request) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", l.Addr().String())
	}
}
func recoveryConnect(t *testing.T, proxy, host string, headers string) (net.Conn, int) {
	t.Helper()
	c, e := net.DialTimeout("tcp4", proxy, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n%s\r\n", host, host, headers)
	response, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		c.Close()
		t.Fatal(e)
	}
	return c, response.StatusCode
}
func TestRecoveryTransportPrimaryOutageAndReturnNoReplay(t *testing.T) {
	_, dial := recoveryEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner := Owner{PID: 7, Birth: 3, Exe: "chrome.exe", Profile: "chrome"}
	var forwarded atomic.Int64
	primaryConfig := Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return owner, nil }, AuthorizeForwarded: func(_ context.Context, _, _, source, listener netip.AddrPort) (Owner, error) {
		if source.Port() == 0 || listener.Port() == 0 {
			t.Error("original tuple missing")
		}
		forwarded.Add(1)
		return owner, nil
	}, Plan: func(context.Context, Request) (Plan, error) {
		return Plan{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil
	}, Open: func(ctx context.Context, q Request, _ Plan) (net.Conn, error) { return dial(ctx, q) }}
	primary, e := Listen(ctx, primaryConfig)
	if e != nil {
		t.Fatal(e)
	}
	address := primary.Address()
	defer func() { primary.Close() }()
	var direct atomic.Int64
	recovery, e := ListenRecovery(ctx, "127.0.0.1:0", func(context.Context, netip.AddrPort, netip.AddrPort, RecoverySettings) (Owner, error) {
		return owner, nil
	}, func(ctx context.Context, q Request) (net.Conn, error) { direct.Add(1); return dial(ctx, q) })
	if e != nil {
		t.Fatal(e)
	}
	defer recovery.Close()
	if e = recovery.Configure(RecoverySettings{Primary: address, Executable: "chrome.exe", Profile: "chrome", Domains: []string{"private.example"}}); e != nil {
		t.Fatal(e)
	}
	check := func() {
		c, status := recoveryConnect(t, recovery.Address(), "ordinary.example", "")
		defer c.Close()
		if status != 200 {
			t.Fatal(status)
		}
		want := []byte("real application bytes")
		if _, e := c.Write(want); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(want))
		if _, e := io.ReadFull(c, got); e != nil || string(got) != string(want) {
			t.Fatal(string(got), e)
		}
	}
	check()
	if forwarded.Load() != 1 || direct.Load() != 0 {
		t.Fatal("healthy primary not used", forwarded.Load(), direct.Load())
	}
	held, status := recoveryConnect(t, recovery.Address(), "ordinary.example", "")
	if status != 200 {
		t.Fatal(status)
	}
	primary.Close()
	// Existing tunnel closes; it must never be retried on a new direct socket.
	held.Write([]byte("must not replay"))
	held.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := held.Read(make([]byte, 1)); e == nil {
		t.Fatal("old stream replayed")
	}
	held.Close()
	if direct.Load() != 0 {
		t.Fatal("existing stream migrated")
	}
	for _, host := range []string{"chatgpt.com", "api.openai.com", "www.youtube.com", "r.googlevideo.com", "private.example"} {
		c, status := recoveryConnect(t, recovery.Address(), host, "")
		c.Close()
		if status == 200 {
			t.Fatal("guarded origin escaped", host)
		}
	}
	if direct.Load() != 0 {
		t.Fatal("guarded attempt opened DIRECT")
	}
	check()
	if direct.Load() != 1 {
		t.Fatal("ordinary outage did not use independent DIRECT")
	}
	primaryConfig.Address = address
	primary, e = Listen(ctx, primaryConfig)
	if e != nil {
		t.Fatal(e)
	}
	check()
	if direct.Load() != 1 || forwarded.Load() != 3 {
		t.Fatal("new flow did not return to planner", direct.Load(), forwarded.Load())
	}
}
func TestForwardedChromeIdentityCannotBeForged(t *testing.T) {
	var opened atomic.Int64
	s, e := Listen(context.Background(), Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return Owner{}, nil }, Plan: func(context.Context, Request) (Plan, error) { opened.Add(1); return Plan{}, nil }, Open: func(context.Context, Request, Plan) (net.Conn, error) { return nil, nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, status := recoveryConnect(t, s.Address(), "chatgpt.com", "Neexitlag-Source: 127.0.0.1:1234\r\nNeexitlag-Listener: 127.0.0.1:4321\r\n")
	c.Close()
	if status != 403 || opened.Load() != 0 {
		t.Fatal("untrusted forwarded tuple reached planner", status, opened.Load())
	}
}
func TestRecoveryNeverTurnsPrimaryRejectionIntoDirect(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			readHeaders(bufio.NewReader(c))
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		}
	}()
	var opened atomic.Int64
	r, e := ListenRecovery(context.Background(), "127.0.0.1:0", func(context.Context, netip.AddrPort, netip.AddrPort, RecoverySettings) (Owner, error) {
		return Owner{}, nil
	}, func(context.Context, Request) (net.Conn, error) { opened.Add(1); return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = r.Configure(RecoverySettings{Primary: l.Addr().String(), Executable: "chrome.exe", Profile: "chrome"}); e != nil {
		t.Fatal(e)
	}
	c, status := recoveryConnect(t, r.Address(), "ordinary.example", "")
	c.Close()
	if status == 200 || opened.Load() != 0 {
		t.Fatal("primary rejection downgraded", status, opened.Load())
	}
}

func TestRecoveryPACGuardsHaveNoSecondaryOrDirectAlternative(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for actual PAC evaluation")
	}
	for _, strict := range []bool{false, true} {
		args, err := ChromeArgumentsWithRecovery("127.0.0.1:1234", `C:\Chrome`, []string{"private.example"}, strict, "127.0.0.1:4321")
		if err != nil {
			t.Fatal(err)
		}
		script, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(args[1], "--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,"))
		if err != nil {
			t.Fatal(err)
		}
		input, _ := json.Marshal(map[string]any{"script": string(script), "names": []string{"ordinary.example", "chatgpt.com", "api.openai.com", "www.youtube.com", "private.example", "openai.com.evil.example"}})
		cmd := exec.Command(node, "-e", `let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>{let x=JSON.parse(s),vm=require('vm'),c={};vm.createContext(c);vm.runInContext(x.script,c);console.log(JSON.stringify(x.names.map(h=>c.FindProxyForURL('https://'+h,h))));});`)
		cmd.Stdin = strings.NewReader(string(input))
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal(err, string(raw))
		}
		var routes []string
		if err = json.Unmarshal(raw, &routes); err != nil {
			t.Fatal(err)
		}
		for i, route := range routes {
			if strings.Contains(route, "DIRECT") {
				t.Fatal("unattributed native bypass", route)
			}
			ordinary := i == 0 || i == 5
			wantSecondary := ordinary && !strict
			if strings.Contains(route, ":4321") != wantSecondary || !strings.Contains(route, ":1234") {
				t.Fatal("guard/secondary mismatch", strict, i, route)
			}
		}
	}
}

func TestRecoveryLiveGuardPreventsStaleDirectAuthorization(t *testing.T) {
	_, dial := recoveryEcho(t)
	unused, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	primary := unused.Addr().String()
	unused.Close()
	var opened atomic.Int64
	r, e := ListenRecovery(context.Background(), "127.0.0.1:0", func(context.Context, netip.AddrPort, netip.AddrPort, RecoverySettings) (Owner, error) {
		return Owner{PID: 1, Birth: 1, Exe: "chrome.exe", Profile: "chrome"}, nil
	}, func(ctx context.Context, q Request) (net.Conn, error) { opened.Add(1); return dial(ctx, q) })
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	file := filepath.Join(t.TempDir(), "browser-recovery-guard.json")
	cfg := RecoverySettings{Primary: primary, Executable: "chrome.exe", Profile: "chrome", GuardFile: file}
	if e = r.Configure(cfg); e != nil {
		t.Fatal(e)
	}
	publish := func(guard RecoveryGuard) {
		raw, _ := json.Marshal(guard)
		temporary := file + ".tmp"
		if e := os.WriteFile(temporary, raw, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Rename(temporary, file); e != nil {
			t.Fatal(e)
		}
	}
	allow := RecoveryGuard{Version: 1, Profiles: map[string]RecoveryGuardProfile{"chrome": {Executables: []string{"chrome.exe"}}}}
	publish(allow)
	c, status := recoveryConnect(t, r.Address(), "ordinary.example", "")
	if status != 200 {
		t.Fatal(status)
	}
	c.Write([]byte("x"))
	if _, e = io.ReadFull(c, make([]byte, 1)); e != nil {
		t.Fatal(e)
	}
	c.Close()
	for _, guard := range []RecoveryGuard{{Version: 1, Deny: true}, {Version: 1, Profiles: map[string]RecoveryGuardProfile{"chrome": {Executables: []string{"chrome.exe"}, Strict: true}}}, {Version: 1, Profiles: map[string]RecoveryGuardProfile{"chrome": {Executables: []string{"chrome.exe"}, Domains: []string{"ordinary.example"}}}}, {Version: 1, Profiles: map[string]RecoveryGuardProfile{}}} {
		publish(guard)
		c, status = recoveryConnect(t, r.Address(), "ordinary.example", "")
		c.Close()
		if status == 200 {
			t.Fatal("stale GUI config bypassed current protected/deleted profile")
		}
	}
	if opened.Load() != 1 {
		t.Fatal("guarded connection opened DIRECT", opened.Load())
	}
	r.AuthorizeMetadata(func(context.Context, netip.AddrPort, netip.AddrPort) error { return nil })
	for _, token := range []string{"wrong", r.MetadataToken()} {
		c, e := net.Dial("tcp4", r.Address())
		if e != nil {
			t.Fatal(e)
		}
		fmt.Fprintf(c, "GET http://neexitlag-recovery-status.invalid/status HTTP/1.1\r\nHost: neexitlag-recovery-status.invalid\r\nAuthorization: Bearer %s\r\n\r\n", token)
		response, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e != nil {
			t.Fatal(e)
		}
		if token == "wrong" {
			if response.StatusCode != 403 {
				t.Fatal("metadata authentication bypass")
			}
		} else {
			var snapshot Snapshot
			if e = json.NewDecoder(response.Body).Decode(&snapshot); e != nil {
				t.Fatal(e)
			}
			if len(snapshot.Records) != 1 || snapshot.Records[0].EvidenceSource != "RECOVERY_DIRECT" || snapshot.Records[0].Sent == 0 || snapshot.Records[0].Received == 0 {
				t.Fatal("missing actual fallback socket bytes", snapshot)
			}
		}
		response.Body.Close()
		c.Close()
	}
}

func TestRecoveryMetadataAcceptsDirectHTTPOriginFormOnlyForPrivateStatus(t *testing.T) {
	r, err := ListenRecovery(context.Background(), "127.0.0.1:0", func(context.Context, netip.AddrPort, netip.AddrPort, RecoverySettings) (Owner, error) {
		t.Error("metadata caller entered Chrome forwarding authentication")
		return Owner{}, ErrOwnerProfile
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.AuthorizeMetadata(func(context.Context, netip.AddrPort, netip.AddrPort) error { return nil })
	for _, test := range []struct {
		host, token string
		status      int
	}{{"neexitlag-recovery-status.invalid", r.MetadataToken(), 200}, {"neexitlag-recovery-status.invalid", "wrong", 403}, {"ordinary.example", r.MetadataToken(), 400}} {
		conn, err := net.Dial("tcp4", r.Address())
		if err != nil {
			t.Fatal(err)
		}
		// HttpClient with UseProxy=false uses origin-form even with a Host override.
		fmt.Fprintf(conn, "GET /status HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n", test.host, test.token)
		reply, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		if reply.StatusCode != test.status {
			t.Fatal(test.host, reply.StatusCode, test.status)
		}
		if test.status == 200 {
			var proof Snapshot
			if err = json.NewDecoder(reply.Body).Decode(&proof); err != nil || !proof.Listening {
				t.Fatal("invalid metadata", err)
			}
		}
		reply.Body.Close()
		conn.Close()
	}
}
