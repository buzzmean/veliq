package browserproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPACOriginKeysAndOfflineFailClosed(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node required to execute PAC; installed on CI")
	}
	names := []string{"chatgpt.com", "www.youtube.com", "ordinary.example", "a-b.example", "a.b-example", strings.Repeat("a", 63) + ".example"}
	input, _ := json.Marshal(map[string]any{"pac": PAC(1234), "names": names})
	js := `let d='';process.stdin.on('data',v=>d+=v);process.stdin.on('end',()=>{const x=JSON.parse(d);const vm=require('vm');let c={};vm.createContext(c);vm.runInContext(x.pac,c,{timeout:100});process.stdout.write(JSON.stringify(x.names.map(n=>c.FindProxyForURL('https://'+n,n))));});`
	cmd := exec.Command(node, "-e", js)
	cmd.Stdin = strings.NewReader(string(input))
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatal(e, string(out))
	}
	var values []string
	if e = json.Unmarshal(out, &values); e != nil {
		t.Fatal(e, string(out))
	}
	for i, name := range names {
		h := sha256.Sum256([]byte(name))
		key := hex.EncodeToString(h[:])
		want := "PROXY " + key[:32] + "." + key[32:] + ".localhost:1234"
		if values[i] != want {
			t.Fatal(name, values[i], want)
		}
	}
	args, e := ChromeArguments("127.0.0.1:1234", `C:\Users\test\Chrome`)
	if e != nil {
		t.Fatal(e)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "data:application/x-ns-proxy-autoconfig;base64,") || strings.Contains(joined, "ignore-certificate") || strings.Contains(joined, "disable-quic") {
		t.Fatal(args)
	}
}
func TestProbeRequiresRealHTTPAndValidTLS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/" || r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" {
			t.Error("probe leaked browser request data")
		}
		w.WriteHeader(200)
	}))
	defer target.Close()
	addr := target.Listener.Addr().String()
	port := uint16(target.Listener.Addr().(*net.TCPAddr).Port)
	open := func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", addr) }
	status, _, why := ProbeOrigin(context.Background(), "example.com", port, true, nil, open)
	if status != 0 || why != "TLS_CERTIFICATE_ERROR" {
		t.Fatal("untrusted TLS accepted", status, why)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer plain.Close()
	p := uint16(plain.Listener.Addr().(*net.TCPAddr).Port)
	status, rx, why := ProbeOrigin(context.Background(), "origin.example", p, false, nil, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", plain.Listener.Addr().String())
	})
	if status != 204 || rx == 0 || why != "" {
		t.Fatal(status, rx, why)
	}
}
func TestOriginTransportNeverReplaysAndRejectsUnauthorizedClients(t *testing.T) {
	var opened atomic.Int32
	cfg := Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
		return Owner{PID: 1, Birth: 1, Exe: "test"}, nil
	}, Plan: func(context.Context, Request) (Plan, error) {
		return Plan{Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}, nil
	}, Open: func(context.Context, Request, Plan) (net.Conn, error) {
		opened.Add(1)
		return nil, fmt.Errorf("relay unavailable")
	}}
	s, e := Listen(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := net.Dial("tcp", s.Address())
	if e != nil {
		t.Fatal(e)
	}
	fmt.Fprint(c, "CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
	resp, e := http.ReadResponse(bufio.NewReader(c), nil)
	c.Close()
	if e != nil || resp.StatusCode != 502 || opened.Load() != 1 {
		t.Fatal(resp, e, opened.Load())
	}
	for _, r := range s.Snapshot().Records {
		if r.Sent != 0 || r.Received != 0 || r.Plan.Policy.Fallback != flowpolicy.Required || r.Result != "UPSTREAM_OPEN_FAILED" {
			t.Fatal(r)
		}
	}
}
func TestCONNECTPreservesPipelinedTLSBytesAndShutdown(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, e := target.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	s, err := Listen(context.Background(), Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return Owner{PID: 1}, nil }, Plan: func(context.Context, Request) (Plan, error) {
		return Plan{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil
	}, Open: func(ctx context.Context, _ Request, _ Plan) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target.Addr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", s.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example\r\n\r\nopaque-first-TLS-bytes")
	b := bufio.NewReader(c)
	_, err = http.ReadResponse(b, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("opaque-first-TLS-bytes"))
	if _, err = io.ReadFull(b, response); err != nil || string(response) != "opaque-first-TLS-bytes" {
		t.Fatal("pipelined data lost", string(response), err)
	}
	// The peer can receive bytes before Write returns and commits accounting.
	// Wait for that commit; the tunnel must remain active throughout the check.
	var snap Snapshot
	until := time.Now().Add(time.Second)
	for {
		snap = s.Snapshot()
		if len(snap.Records) == 1 && snap.Records[0].Active && snap.Records[0].Sent > 0 && snap.Records[0].Received > 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("missing live tunnel counters", snap)
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle tunnel prevents service stop")
	}
}

func TestUnauthorizedOwnerCannotOpenOrigin(t *testing.T) {
	var opened atomic.Int32
	s, e := Listen(context.Background(), Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
		return Owner{}, fmt.Errorf("wrong owner")
	}, Plan: func(context.Context, Request) (Plan, error) { opened.Add(1); return Plan{}, nil }, Open: func(context.Context, Request, Plan) (net.Conn, error) { opened.Add(1); return nil, nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := net.Dial("tcp", s.Address())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(c, "CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
	r, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil || r.StatusCode != 403 || opened.Load() != 0 {
		t.Fatal(r, e, opened.Load())
	}
}

func TestFailedOriginPlanRetainsBoundedEvidence(t *testing.T) {
	s, e := Listen(context.Background(), Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return Owner{PID: 1}, nil }, Plan: func(context.Context, Request) (Plan, error) { return Plan{}, context.DeadlineExceeded }, Open: func(context.Context, Request, Plan) (net.Conn, error) {
		t.Error("opened after planning failure")
		return nil, fmt.Errorf("unexpected")
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := net.Dial("tcp", s.Address())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	fmt.Fprint(c, "CONNECT unknown.example:443 HTTP/1.1\r\nHost: unknown.example:443\r\n\r\n")
	r, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil || r.StatusCode != 502 {
		t.Fatal(r, e)
	}
	snap := s.Snapshot()
	if len(snap.Records) != 1 || snap.Records[0].Plan.Probe != "NETWORK_TIMEOUT" || snap.Records[0].Result != "ORIGIN_PLAN_FAILED" || snap.Records[0].Active {
		t.Fatal(snap)
	}
}

func TestPlainHTTPForwardsAndCountsActualBytes(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/real" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("wrong request or proxy credentials forwarded")
		}
		fmt.Fprint(w, "real response")
	}))
	defer target.Close()
	s, e := Listen(context.Background(), Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return Owner{PID: 1}, nil }, Plan: func(context.Context, Request) (Plan, error) {
		return Plan{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil
	}, Open: func(ctx context.Context, _ Request, _ Plan) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target.Listener.Addr().String())
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := net.Dial("tcp", s.Address())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(c, "GET http://ordinary.example/real HTTP/1.1\r\nHost: ordinary.example\r\nProxy-Authorization: do-not-forward\r\n\r\n")
	response, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || string(raw) != "real response" {
		t.Fatal(string(raw), e)
	}
	until := time.Now().Add(time.Second)
	for {
		snap := s.Snapshot()
		if len(snap.Records) == 1 && !snap.Records[0].Active {
			r := snap.Records[0]
			if r.Sent == 0 || r.Received == 0 || r.Result != "HTTP_RESPONSE" {
				t.Fatal(r)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal("missing completed HTTP evidence", snap)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestChromeHealthRequiresAuthorizedOwnerAndExactNonce(t *testing.T) {
	var authorized atomic.Bool
	s, err := Listen(context.Background(), Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
		if !authorized.Load() {
			return Owner{}, ErrOwnerSID
		}
		return Owner{PID: 10, Profile: "chrome"}, nil
	}, Plan: func(context.Context, Request) (Plan, error) {
		t.Error("health used origin planner")
		return Plan{}, nil
	}, Open: func(context.Context, Request, Plan) (net.Conn, error) {
		t.Error("health opened origin")
		return nil, fmt.Errorf("unexpected")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	url, err := s.Challenge("chrome")
	if err != nil {
		t.Fatal(err)
	}
	get := func(url string) int {
		c, e := net.Dial("tcp4", s.Address())
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: neexitlag-health.invalid\r\n\r\n", url)
		r, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e != nil {
			t.Fatal(e)
		}
		return r.StatusCode
	}
	if get(url) != 403 || s.Confirmed("chrome") {
		t.Fatal("unauthorized socket confirmed readiness")
	}
	authorized.Store(true)
	if get(url+"wrong") != 403 || s.HealthVerified("chrome", url) {
		t.Fatal("guessed nonce confirmed readiness")
	}
	if get(url) != 200 || !s.HealthVerified("chrome", url) {
		t.Fatal("actual Chrome readiness missing")
	}
	if s.Confirmed("chrome") {
		t.Fatal("health response alone published AUTO authority")
	}
	if !s.AuthorizeProfile("chrome", url) || !s.Confirmed("chrome") {
		t.Fatal("validated activation not committed")
	}

	if get(url) != 403 {
		t.Fatal("replayed activation nonce accepted")
	}
	if !s.HealthVerified("chrome", url) {
		t.Fatal("lost IPC confirmation response not recoverable")
	}
	if s.Snapshot().Failures["OWNER_SID_MISMATCH"] != 1 {
		t.Fatal("owner failure evidence missing", s.Snapshot())
	}
	next, _ := s.Challenge("chrome")
	if s.HealthVerified("chrome", url) || s.HealthVerified("chrome", next) {
		t.Fatal("previous proof certified a new activation")
	}
	s.Forget("chrome")
	if s.Confirmed("chrome") || get(next) != 403 {
		t.Fatal("recovery retained stale readiness authority")
	}
}

func TestSeparateRecoveryPACNeverLeaksProtectedOrigins(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required on CI")
	}
	for _, strict := range []bool{false, true} {
		args, err := ChromeRecoveryArguments("127.0.0.1:1234", "fixture", []string{"private.example"}, strict)
		if err != nil {
			t.Fatal(err)
		}
		const prefix = "--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,"
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(args[1], prefix))
		if err != nil {
			t.Fatal(err)
		}
		input, _ := json.Marshal(map[string]any{"pac": string(raw), "names": []string{"chatgpt.com", "api.openai.com", "www.youtube.com", "private.example", "vk.com", "openai.com.evil.test"}})
		cmd := exec.Command(node, "-e", `let d='';process.stdin.on('data',x=>d+=x);process.stdin.on('end',()=>{let x=JSON.parse(d),c={};require('vm').runInNewContext(x.pac,c);console.log(JSON.stringify(x.names.map(h=>c.FindProxyForURL('https://'+h,h))));});`)
		cmd.Stdin = strings.NewReader(string(input))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal(err, string(out))
		}
		var routes []string
		if err = json.Unmarshal(out, &routes); err != nil {
			t.Fatal(err, string(out))
		}
		for i, route := range routes {
			if i < 4 || strict {
				if !strings.HasPrefix(route, "PROXY ") || strings.Contains(route, "DIRECT") {
					t.Fatal("protected recovery fallback", routes)
				}
			} else if route != "DIRECT" {
				t.Fatal("ordinary recovery broken", routes)
			}
		}
	}
}
