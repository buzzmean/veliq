//go:build windows

package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/internal/browserfixture"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

// Each pool captures its immutable server, including after a real restart.
// Every QUIC session still authenticates with mTLS and a fresh one-shot ticket.
func newOriginReuseRelay(t *testing.T, c *Controller) (*relay.Server, *transport.Pool) {
	t.Helper()
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 2 * time.Minute, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	pool, err := transport.NewPool(c.ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
		id, err := security.NewID()
		if err != nil {
			return nil, err
		}
		now := time.Now()
		ticket, err := security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "origin-reuse", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			return nil, err
		}
		return transport.DialWithTicket(ctx, r.Addr().String(), ct, ticket)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	c.Engine.SetRelay("VPS-01", pool)
	return r, pool
}

type originReuseOutage struct {
	mode        string
	c           *Controller
	f           *browserfixture.OriginReuse
	proxy       func() *browserproxy.Server
	relay       func() (uint64, uint64)
	down, up    func()
	before      nativeBrowserSnapshot
	tcp, rx     uint64
	independent map[uint64]bool
	beforePAC   browserproxy.Snapshot
}

func (o *originReuseOutage) boundary(t *testing.T, recovery bool) {
	t.Helper()
	if o.c.chromePolicyActive() {
		t.Fatal("outage requires withdrawn owned policy")
	}
	o.before = o.c.nativeSnapshot()
	o.tcp, o.rx = o.relay()
	start := 0
	if recovery {
		start = 2
	}
	for _, r := range o.before.Records {
		if r.Domain == browserfixture.OutageHosts[start] || r.Domain == browserfixture.OutageHosts[start+1] {
			t.Fatal("outage authority used before boundary")
		}
	}
	t.Logf("ORIGIN_OUTAGE_BOUNDARY mode=%s recovery=%t registry_active=false capture_ready=%t listener=%t new_authorities=true same_pid_birth=true", o.mode, recovery, o.c.nativeBackendReady(), o.proxy().Snapshot().Listening)
}

func (o *originReuseOutage) phase(t *testing.T, stage string) {
	t.Helper()
	switch stage {
	case "before_outage":
		o.down()
		capture := (strings.Contains(o.mode, "-capture-") || strings.Contains(o.mode, "-combined-"))
		listener := (strings.Contains(o.mode, "-listener-") || strings.Contains(o.mode, "-combined-"))
		if o.c.nativeBackendReady() == capture || o.proxy().Snapshot().Listening == listener {
			t.Fatal("actual component outage not established")
		}
		o.boundary(t, false)
	case "outage_direct":
		o.verifyPhase(t, false)
	case "before_recovery":
		o.up()
		if !o.c.nativeBackendReady() || !o.proxy().Snapshot().Listening {
			t.Fatal("component recovery not established")
		}
		o.boundary(t, true)
	case "recovery_direct":
		o.verifyPhase(t, true)
	case "before_retry":
		o.before = o.c.nativeSnapshot()
		o.beforePAC = o.proxy().Snapshot()
		o.tcp, o.rx = o.relay()
		t.Logf("ORIGIN_RETRY_BOUNDARY mode=%s same_authorities=true browser_cache_reset=false", o.mode)
	case "retry_direct":
		o.verifyRetry(t)
	}
}

func (o *originReuseOutage) verifyPhase(t *testing.T, recovery bool) {
	t.Helper()
	requests, outcomes := o.f.OutageEvidence(t)
	start := 0
	if recovery {
		start = 2
	}
	if len(outcomes) != start+2 {
		t.Fatal("outage browser outcomes incomplete")
	}
	after, pac := o.c.nativeSnapshot(), o.proxy().Snapshot()
	if after.Lost != 0 || after.Truncated || pac.Lost != 0 || pac.Truncated {
		t.Fatal("outage application evidence incomplete")
	}
	var exchanges int
	for i := start; i < start+2; i++ {
		host, step := browserfixture.OutageHosts[i], browserfixture.OutageSteps[i]
		outcome := outcomes[i]
		wantSuccess := recovery || (i%2 == 1 && ((strings.Contains(o.mode, "-listener-") && strings.HasSuffix(o.mode, "-availability")) || strings.Contains(o.mode, "-relay-")))
		if !recovery && strings.Contains(o.mode, "-capture-") {
			wantSuccess = true
		}
		if !recovery && i%2 == 1 && strings.Contains(o.mode, "-combined-") && strings.HasSuffix(o.mode, "-availability") {
			wantSuccess = true
		}
		if outcome.Step != step || outcome.Complete != wantSuccess {
			t.Errorf("outage availability mismatch: mode=%s step=%s complete=%t expected=%t error=%s", o.mode, step, outcome.Complete, wantSuccess, outcome.Error)
		}
		t.Logf("ORIGIN_OUTAGE_BROWSER mode=%s step=%s complete=%t error=%s elapsed_ms=%d", o.mode, step, outcome.Complete, outcome.Error, outcome.Millis)
		count := 0
		for _, q := range requests {
			if q.Step != step {
				continue
			}
			count++
			t.Logf("ORIGIN_OUTAGE_REQUEST mode=%s %+v", o.mode, q)
			wantSource := "127.0.0.1"
			if i%2 == 0 {
				wantSource = "127.0.0.2"
			}
			if q.Source != wantSource {
				t.Error("ORIGIN_OUTAGE_ROUTE_VIOLATION", step, q.Source)
			}
			ordinaryWithoutCapture := !recovery && i%2 == 1 && strings.Contains(o.mode, "-combined-") && strings.HasSuffix(o.mode, "-availability")
			if q.Host != host || (!ordinaryWithoutCapture && q.SNI != host) || q.Protocol != 2 || q.BodyBytes != len(o.f.Nonce+":"+step) {
				t.Error("outage H2 authority/body evidence incomplete", step)
			}
		}
		if (!outcome.Complete && count != 0) || (outcome.Complete && count != 1) {
			t.Error("outage server request and browser outcome disagree", step, count)
		}
		witnessed := false
		for _, r := range after.Records {
			if r.Domain != host {
				continue
			}
			t.Logf("ORIGIN_OUTAGE_NATIVE mode=%s step=%s ingress=%s action=%s sent=%d received=%d", o.mode, step, r.Ingress, r.Policy.Action, r.Sent, r.Received)
			if r.Sent == 0 || r.Received == 0 {
				continue
			}
			want := flowpolicy.Direct
			if i%2 == 0 {
				want = flowpolicy.RelayRequired
			}
			if r.Owner.Profile != "origin-reuse" || r.Owner.PID == 0 || r.Owner.Birth == 0 || r.Policy.Action != want || (i%2 == 0 && r.Policy.Fallback != flowpolicy.Required) {
				t.Error("outage current owner/route/floor mismatch", step)
			}
			if r.Ingress != "NATIVE_TCP" && r.Ingress != "PAC_NATIVE_UPSTREAM" {
				t.Error("outage ingress unproven", step)
			}
			if !recovery && strings.Contains(o.mode, "-listener-") && r.Ingress != "NATIVE_TCP" {
				t.Error("closed listener cannot provide fresh PAC ingress")
			}
			if r.Ingress == "PAC_NATIVE_UPSTREAM" {
				matched := false
				for _, p := range pac.Records {
					if p.Domain == host && p.Sent > 0 && p.Received > 0 && p.Plan.Policy.Action == want {
						matched = true
					}
				}
				if !matched {
					t.Error("outage CONNECT and native upstream disagree", step)
				}
			}
			witnessed = true
		}
		for _, r := range pac.Records {
			if r.Domain == host {
				t.Logf("ORIGIN_OUTAGE_CONNECT mode=%s step=%s result=%s failure=%s", o.mode, step, r.Result, r.OpenFailure)
			}
		}
		if !recovery && strings.Contains(o.mode, "-capture-") && outcome.Complete {
			if o.c.nativeBackendReady() {
				t.Fatal("capture-independent phase unexpectedly has capture")
			}
			for _, record := range pac.Records {
				if record.Domain != host || record.Sent == 0 || record.Received == 0 {
					continue
				}
				want := flowpolicy.Direct
				if i%2 == 0 {
					want = flowpolicy.RelayRequired
				}
				if record.Owner.Profile != "origin-reuse" || record.Owner.PID == 0 || record.Owner.Birth == 0 || record.Plan.Policy.Action != want || record.Plan.Network != "isolated-origin-reuse" || (i%2 == 0 && record.Plan.Policy.Fallback != flowpolicy.Required) {
					t.Error("capture-independent PAC owner/route/floor mismatch", step)
				}
				t.Logf("ORIGIN_CAPTURE_INDEPENDENT step=%s action=%s sent=%d received=%d capture_ready=false", step, record.Plan.Policy.Action, record.Sent, record.Received)
				if o.independent == nil {
					o.independent = map[uint64]bool{}
				}
				o.independent[record.ID] = true
				witnessed = true
			}
		}
		if outcome.Complete {
			exchanges++
			if !witnessed && !(i%2 == 1 && !recovery && strings.Contains(o.mode, "-combined-") && strings.HasSuffix(o.mode, "-availability")) {
				t.Error("outage successful response lacks real capture/owner evidence", step)
			}
		}
	}
	tcp, rx := o.relay()
	if tcp < o.tcp || rx < o.rx {
		t.Fatal("relay counter epoch changed inside phase")
	}
	if outcomes[start].Complete && (tcp == o.tcp || rx == o.rx) {
		t.Error("fresh required authenticated relay increments missing")
	}
	if !outcomes[start].Complete && tcp != o.tcp {
		t.Error("blocked REQUIRED or ordinary DIRECT unexpectedly opened relay")
	}
	if exchanges > 0 && !(!recovery && (strings.Contains(o.mode, "-combined-") || strings.Contains(o.mode, "-capture-"))) && (after.CaptureIngress == nil || o.before.CaptureIngress == nil || after.CaptureIngress.TCPPackets <= o.before.CaptureIngress.TCPPackets || after.CaptureIngress.ReflectedAccepts <= o.before.CaptureIngress.ReflectedAccepts) {
		t.Error("outage phase actual capture increments missing")
	}
	t.Logf("ORIGIN_OUTAGE_PROOF mode=%s recovery=%t relay_tcp_delta=%d relay_rx_delta=%d complete=%d", o.mode, recovery, tcp-o.tcp, rx-o.rx, exchanges)
}

func (o *originReuseOutage) verifyRetry(t *testing.T) {
	t.Helper()
	requests, outcomes := o.f.OutageEvidence(t)
	if len(outcomes) != 6 || !o.c.nativeBackendReady() || !o.proxy().Snapshot().Listening || o.c.chromePolicyActive() {
		t.Fatal("same-authority retry lifecycle incomplete")
	}
	after, pac := o.c.nativeSnapshot(), o.proxy().Snapshot()
	if after.Lost != 0 || after.Truncated || pac.Lost != 0 || pac.Truncated {
		t.Fatal("retry evidence incomplete")
	}
	for i, step := range browserfixture.OutageRetrySteps {
		outcome := outcomes[4+i]
		t.Logf("ORIGIN_RETRY_BROWSER mode=%s step=%s complete=%t error=%s elapsed_ms=%d", o.mode, step, outcome.Complete, outcome.Error, outcome.Millis)
		if outcome.Step != step || !outcome.Complete {
			t.Error("same failed authority did not recover", step)
		}
		count := 0
		for _, q := range requests {
			if q.Step != step {
				continue
			}
			count++
			want := "127.0.0.1"
			if i == 0 {
				want = "127.0.0.2"
			}
			t.Logf("ORIGIN_RETRY_REQUEST mode=%s %+v", o.mode, q)
			if q.Host != browserfixture.OutageHosts[i] || q.Source != want || q.Protocol != 2 || q.BodyBytes != len(o.f.Nonce+":"+step) {
				t.Error("same-authority retry route/body mismatch", step)
			}
		}
		if count != 1 {
			t.Error("retry server cardinality mismatch", step, count)
		}
	}
	previousSent, previousReceived := map[uint64]uint64{}, map[uint64]uint64{}
	for _, r := range o.before.Records {
		previousSent[r.ID] = r.Sent
		previousReceived[r.ID] = r.Received
	}
	witnessed := false
	for _, r := range after.Records {
		if r.Domain != browserfixture.OutageHosts[0] || r.Sent <= previousSent[r.ID] || r.Received <= previousReceived[r.ID] {
			continue
		}
		t.Logf("ORIGIN_RETRY_NATIVE mode=%s ingress=%s action=%s sent=%d received=%d", o.mode, r.Ingress, r.Policy.Action, r.Sent, r.Received)
		if r.Owner.Profile != "origin-reuse" || r.Owner.PID == 0 || r.Owner.Birth == 0 || r.Policy.Action != flowpolicy.RelayRequired || r.Policy.Fallback != flowpolicy.Required || r.Ingress != "PAC_NATIVE_UPSTREAM" {
			t.Error("retry required owner/ingress/floor mismatch")
		}
		witnessed = true
	}
	reusedIndependent := false
	if !witnessed && strings.Contains(o.mode, "-capture-") {
		prior := map[uint64]browserproxy.Record{}
		for _, record := range o.beforePAC.Records {
			prior[record.ID] = record
		}
		for _, record := range pac.Records {
			if !o.independent[record.ID] || record.Domain != browserfixture.OutageHosts[0] || record.Sent <= prior[record.ID].Sent || record.Received <= prior[record.ID].Received {
				continue
			}
			if record.Owner.Profile != "origin-reuse" || record.Owner.PID == 0 || record.Owner.Birth == 0 || record.Plan.Policy.Action != flowpolicy.RelayRequired || record.Plan.Policy.Fallback != flowpolicy.Required {
				t.Error("retry reused PAC owner/floor mismatch")
			}
			t.Logf("ORIGIN_RETRY_PINNED_CAPTURE_INDEPENDENT id=%d sent_delta=%d received_delta=%d", record.ID, record.Sent-prior[record.ID].Sent, record.Received-prior[record.ID].Received)
			reusedIndependent = true
			witnessed = true
		}
	}
	if !witnessed {
		t.Error("retry required actual transport exchange missing")
	}
	tcp, rx := o.relay()
	if tcp < o.tcp || rx <= o.rx || (!reusedIndependent && (after.CaptureIngress == nil || o.before.CaptureIngress == nil || after.CaptureIngress.TCPPackets <= o.before.CaptureIngress.TCPPackets)) {
		t.Error("retry capture/authenticated relay byte increments missing")
	}
	t.Logf("ORIGIN_RETRY_PROOF mode=%s relay_tcp_delta=%d relay_rx_delta=%d", o.mode, tcp-o.tcp, rx-o.rx)
}

func (o *originReuseOutage) verifyFinal(t *testing.T) {
	t.Helper()
	requests, outcomes := o.f.OutageEvidence(t)
	if len(outcomes) != 6 || o.c.chromePolicyActive() {
		t.Fatal("outage sequence incomplete or policy unexpectedly restored")
	}
	connections := map[uint64]bool{o.f.Bootstrap(t).Connection: true}
	for _, r := range o.f.Requests(t) {
		connections[r.Connection] = true
	}
	counts := map[string]int{}
	for _, r := range requests {
		ordinaryWithoutCapture := r.Step == "retry_direct" || r.Step == "retry_required" || r.Step == "outage_direct" && strings.Contains(o.mode, "-combined-") && strings.HasSuffix(o.mode, "-availability")
		if connections[r.Connection] && !ordinaryWithoutCapture {
			t.Error("outage/recovery authority reused an earlier origin connection", r.Step)
		}
		connections[r.Connection] = true
		counts[r.Step]++
	}
	for _, outcome := range outcomes {
		want := 0
		if outcome.Complete {
			want = 1
		}
		if counts[outcome.Step] != want {
			t.Error("late or duplicate outage request", outcome.Step)
		}
	}
}
