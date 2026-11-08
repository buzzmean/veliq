package clientservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

// Сначала подписка, затем snapshot: между чтением и ожиданием событие не теряется.
// Это только измерение fixture, не новый критерий готовности production.
func observeNativeRouteProof(c *Controller) (nativeBrowserSnapshot, <-chan struct{}) {
	n := &c.browser.native
	n.mu.Lock()
	if n.changed == nil {
		n.changed = make(chan struct{})
	}
	changed := n.changed
	n.mu.Unlock()
	return c.nativeSnapshot(), changed
}
func checkNativeRouteProof(s nativeBrowserSnapshot, driver bool) ([]uint64, error) {
	if s.Truncated || s.Lost != 0 {
		return nil, errors.New("NATIVE_ROUTE_EVIDENCE_LOST")
	}
	if s.NativeOnly.Accepted == 0 || s.NativeOnly.Opened == 0 || s.NativeOnly.Exchanges == 0 || s.PACUpstream.Accepted != 0 {
		return nil, errors.New("NATIVE_ROUTE_EXCHANGE_OR_INGRESS_NOT_PROVEN")
	}
	controlled, exchanges := 0, 0
	var pending []uint64
	for _, r := range s.Records {
		if driver && r.Domain != "native-active.native-browser.test" {
			continue
		}
		controlled++
		// Даже выбранный DIRECT до публикации opened не должен скрыться за PLANNING.
		if r.Policy.Action != "" && (r.Policy.Action != flowpolicy.RelayRequired || r.Policy.RelayID != "VPS-01" || r.Policy.Fallback != flowpolicy.Required) {
			return nil, fmt.Errorf("ACTUAL_ROUTE_LEAK flow=%d state=%s action=%s relay=%s fallback=%s", r.ID, r.Result, r.Policy.Action, r.Policy.RelayID, r.Policy.Fallback)
		}
		if r.Result == "PLANNING" || r.Policy.Action == "" || r.Upstream == "" {
			if !r.Active || r.Failure != "" || r.Result != "PLANNING" && r.Result != "TUNNEL_OPENED" {
				return nil, fmt.Errorf("NATIVE_ROUTE_INCOMPLETE flow=%d state=%s active=%t", r.ID, r.Result, r.Active)
			}
			pending = append(pending, r.ID)
			continue
		}
		switch r.Result {
		case "TUNNEL_OPENED":
		case "BIDIRECTIONAL_EXCHANGE":
			if r.Sent == 0 || r.Received == 0 {
				return nil, fmt.Errorf("NATIVE_ROUTE_BYTES_NOT_PROVEN flow=%d", r.ID)
			}
			exchanges++
		default:
			return nil, fmt.Errorf("NATIVE_ROUTE_NOT_OPENED flow=%d state=%s failure=%s", r.ID, r.Result, r.Failure)
		}
	}
	if controlled == 0 || exchanges == 0 {
		return nil, errors.New("NATIVE_CONTROLLED_HTTP_EXCHANGE_NOT_PROVEN")
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i] < pending[j] })
	return pending, nil
}
func awaitNativeRouteProof(ctx context.Context, driver bool, observe func() (nativeBrowserSnapshot, <-chan struct{})) (nativeBrowserSnapshot, error) {
	for {
		snapshot, changed := observe()
		pending, err := checkNativeRouteProof(snapshot, driver)
		if err != nil {
			return snapshot, err
		}
		if len(pending) == 0 {
			return snapshot, nil
		}
		select {
		case <-ctx.Done():
			return snapshot, fmt.Errorf("NATIVE_ROUTE_PROOF_INCOMPLETE pending=%v: %w", pending, ctx.Err())
		case <-changed:
		}
	}
}

func nativeRouteProofFixture(t *testing.T) (*Controller, browserproxy.Request, wp.Tuple, browserproxy.Plan) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	q := browserproxy.Request{Ingress: "NATIVE_TCP", Host: "native-active.native-browser.test", Owner: browserproxy.Owner{PID: 7, Birth: 13, Exe: `C:\Fixture\chrome.exe`, Profile: "native-browser"}}
	tuple := policyTuple("tcp", 443)
	plan := browserproxy.Plan{Destination: netip.MustParseAddrPort("127.0.0.2:443"), Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}
	c.browser.native.activate(q.Owner.Profile, true)
	id, e := c.browser.native.begin(q, tuple)
	if e != nil {
		t.Fatal(e)
	}
	c.browser.native.opened(id, plan, nil)
	c.browser.native.bytes(id, 471, 209)
	c.browser.native.closed(id)
	return c, q, tuple, plan
}
func TestNativeRouteProofWaitsForPlanningWithoutInventingLeak(t *testing.T) {
	c, q, tuple, plan := nativeRouteProofFixture(t)
	id, e := c.browser.native.begin(q, tuple)
	if e != nil {
		t.Fatal(e)
	}
	pending, e := checkNativeRouteProof(c.nativeSnapshot(), true)
	if e != nil || len(pending) != 1 || pending[0] != id {
		t.Fatal("PLANNING must be pending, never PASS or a proven leak", pending, e)
	}
	observed := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		first := true
		s, e := awaitNativeRouteProof(context.Background(), true, func() (nativeBrowserSnapshot, <-chan struct{}) {
			s, ch := observeNativeRouteProof(c)
			if first {
				first = false
				close(observed)
			}
			return s, ch
		})
		if e == nil {
			for _, r := range s.Records {
				if r.ID == id && r.Result != "TUNNEL_OPENED" {
					e = errors.New("unfinished flow accepted")
				}
			}
		}
		done <- e
	}()
	<-observed
	c.browser.native.opened(id, plan, nil)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestNativeRouteProofPlanningCancellationIsIncomplete(t *testing.T) {
	c, q, tuple, _ := nativeRouteProofFixture(t)
	if _, e := c.browser.native.begin(q, tuple); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, e := awaitNativeRouteProof(ctx, true, func() (nativeBrowserSnapshot, <-chan struct{}) {
		s, ch := observeNativeRouteProof(c)
		cancel()
		return s, ch
	})
	if !errors.Is(e, context.Canceled) || !strings.Contains(e.Error(), "PROOF_INCOMPLETE") {
		t.Fatal("unfinished flow became PASS", e)
	}
}
func TestNativeRouteProofActualDirectAlwaysFails(t *testing.T) {
	for _, planning := range []bool{false, true} {
		c, q, tuple, plan := nativeRouteProofFixture(t)
		id, e := c.browser.native.begin(q, tuple)
		if e != nil {
			t.Fatal(e)
		}
		plan.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen}
		c.browser.native.opened(id, plan, nil)
		if planning {
			c.browser.native.mu.Lock()
			r := c.browser.native.records[id]
			r.Result = "PLANNING"
			c.browser.native.records[id] = r
			c.browser.native.mu.Unlock()
		}
		_, e = awaitNativeRouteProof(context.Background(), true, func() (nativeBrowserSnapshot, <-chan struct{}) { return observeNativeRouteProof(c) })
		if e == nil || !strings.Contains(e.Error(), "ACTUAL_ROUTE_LEAK") {
			t.Fatal("real DIRECT escaped assertion", planning, e)
		}
	}
}
func TestNativeRouteProofBlockedLostAndUnknownNeverPass(t *testing.T) {
	for _, kind := range []string{"blocked", "closed-planning", "no-policy", "lost", "truncated", "no-bytes", "wrong-relay", "fail-open", "no-controlled"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, _ := nativeRouteProofFixture(t)
			s := c.nativeSnapshot()
			switch kind {
			case "blocked":
				s.Records[0].Result = "BLOCK"
				s.Records[0].Failure = "OPEN_FAILED"
			case "closed-planning":
				s.Records[0].Result = "PLANNING"
			case "no-policy":
				s.Records[0].Policy = flowpolicy.Result{}
			case "lost":
				s.Lost++
			case "truncated":
				s.Truncated = true
			case "no-bytes":
				s.Records[0].Received = 0
			case "wrong-relay":
				s.Records[0].Policy.RelayID = "OTHER"
			case "fail-open":
				s.Records[0].Policy.Fallback = flowpolicy.FailOpen
			case "no-controlled":
				s.Records[0].Domain = "other.example"
			}
			if pending, e := checkNativeRouteProof(s, true); e == nil {
				t.Fatal("unproven route became PASS", pending)
			}
		})
	}
}
func TestNativeRouteProofSubscriptionCannotMissOpenedBoundary(t *testing.T) {
	c, q, tuple, plan := nativeRouteProofFixture(t)
	if c.browser.native.changed != nil {
		t.Fatal("normal runtime allocated subscriber channel")
	}
	id, e := c.browser.native.begin(q, tuple)
	if e != nil {
		t.Fatal(e)
	}
	first := true
	_, e = awaitNativeRouteProof(context.Background(), true, func() (nativeBrowserSnapshot, <-chan struct{}) {
		s, ch := observeNativeRouteProof(c)
		if first {
			first = false
			c.browser.native.opened(id, plan, nil)
		}
		return s, ch
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestNativeRouteProofRealDirectSocketRejected(t *testing.T) {
	c, q, tuple, plan := nativeRouteProofFixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		peer, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer peer.Close()
		_, e = peer.Write([]byte("real DIRECT response"))
		done <- e
	}()
	upstream, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.browser.native.begin(q, tuple)
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	plan.Destination = listener.Addr().(*net.TCPAddr).AddrPort()
	plan.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen}
	c.browser.native.opened(id, plan, nil)
	conn := newNativeBrowserConn(upstream, &c.browser.native, id)
	reply, err := io.ReadAll(conn)
	conn.Close()
	if err != nil || len(reply) == 0 {
		t.Fatal("DIRECT fault injection did not transfer data", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = checkNativeRouteProof(c.nativeSnapshot(), true); err == nil || !strings.Contains(err.Error(), "ACTUAL_ROUTE_LEAK") {
		t.Fatal("real DIRECT socket became PASS", err)
	}
}
