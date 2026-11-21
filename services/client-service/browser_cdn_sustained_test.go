package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
)

func feedSustainedWire(m *youtubeMeter, now time.Time) {
	for i := 0; i < 65; i++ {
		record := append([]byte{23, 3, 3, 0x40, 0}, make([]byte, 16384)...)
		m.wire.ObserveOrigin(record)
	}
	m.rx = 65*16389 + 47
	m.tx = 4500
	m.healthy = true
	m.applied = true
	m.postHelloWrite = true
	m.firstApplicationRX = now.Add(-4 * time.Second)
	m.lastReply = now
	m.firstClientWrite = now.Add(-5 * time.Second)
	m.serverHelloAt = now.Add(-4900 * time.Millisecond)
}
func TestStrongRunningCDNPromotionIsBoundedScopedAndLateFailureRevokes(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
	now := time.Now()
	feedSustainedWire(m, now)
	m.maybePromoteTrial(now)
	if !m.promoted || r.trialActive || r.selection.TrialSuccesses != 1 || r.selection.StrongPromotions != 1 {
		t.Fatal(r.snapshot())
	}
	if v := r.cache[k]; v.Stage != "LOCAL" || v.Strategy != id || !v.Confirmed || !v.Until.Equal(now.Add(youtubeLearnTTL)) {
		t.Fatal(v)
	}
	other := k
	other.Domain = "googlevideo:sn-other"
	r.completeCDNQualification(other, id, now)
	if _, ok := r.takeTrial(other, now, testSibling(true)); !ok {
		t.Fatal("successful live connection blocked peer subgroup")
	}
	m.maybePromoteTrial(now.Add(time.Second))
	m.Close()
	if !r.trialActive || r.trialKey != other || r.selection.TrialSuccesses != 1 {
		t.Fatal("late Close released another trial")
	}
	m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	if r.cache[k].Stage != "RELAY" || r.selection.PostPromotionFailures != 1 || r.selection.FailedAfterReply != 1 || r.records[1].TrialResult != "SUCCESS_REVOKED_AFTER_FAILURE" {
		t.Fatal("late failure hidden", r.snapshot())
	}
	if v := r.failures[len(r.failures)-1]; v.RX < cdnStrongBytes || v.SinceClientHelloMS < 0 || v.SinceLastRXMS < 0 || v.ApplicationRecords < cdnStrongRecords || !v.Promoted {
		t.Fatal("missing failure timing/volume", v)
	}
	if !r.cache[k].TrialAfter.After(time.Now().Add(2 * time.Minute)) {
		t.Fatal("failure cooldown lost")
	}
}
func TestStrongPromotionCannotBeCertificateBytesBurstOrUncommitted(t *testing.T) {
	for _, variant := range []string{"small", "fast-burst", "uncommitted", "no-post-hello-write", "no-app-records", "stale-rx"} {
		t.Run(variant, func(t *testing.T) {
			m, r, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{}, io.EOF)
			now := time.Now()
			feedSustainedWire(m, now)
			switch variant {
			case "small":
				m.rx = 65000
			case "fast-burst":
				m.firstApplicationRX = now.Add(-100 * time.Millisecond)
			case "uncommitted":
				m.applied = false
			case "no-post-hello-write":
				m.postHelloWrite = false
			case "stale-rx":
				m.lastReply = now.Add(-4 * time.Second)
				m.firstApplicationRX = now.Add(-8 * time.Second)
			case "no-app-records":
				m.wire = browserproxy.TLSWireObserver{}
			}
			m.maybePromoteTrial(now)
			if m.promoted || !r.trialActive || r.selection.TrialSuccesses != 0 {
				t.Fatal("false sustained proof", variant)
			}
		})
	}
}
func TestSmallRemoteEOFIsInconclusiveWithoutHidingRSTOrTimeout(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{FirstClose: "REMOTE_PACKET", FirstCloseFlags: 17, RemoteFIN: 1}, io.EOF)
	m.rx = 2717
	m.Read(make([]byte, 100))
	m.Close()
	if m.failed || r.selection.TrialFailures != 0 || r.selection.FailedAfterReply != 0 || r.selection.RemoteSmallEOFInconclusive != 1 || r.cache[k].Qualified != id || r.cache[k].Tried != 0 {
		t.Fatal(r.snapshot())
	}
	m2, r2, _, _ := trialMeterFixture(t, localstrategy.TCPTrace{RemoteRST: 1}, io.EOF)
	m2.Read(make([]byte, 100))
	m2.Close()
	if !m2.failed || r2.selection.FailedAfterReply != 1 {
		t.Fatal("RST hidden by small EOF")
	}
}
func TestRunningCDNReleasesSlotBeforeCloseAndKeepsExactTLSConnection(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.Backend = &youtubeTransformFixture{}
	var requests, opens atomic.Int32
	server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			io.WriteString(w, "same established TLS")
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(5*256*1024))
		for i := 0; i < 5; i++ {
			if i > 0 {
				time.Sleep(850 * time.Millisecond)
			}
			if _, e := w.Write(bytes.Repeat([]byte{42}, 256*1024)); e != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	r := c.browser.youtube
	k := youtubeScope(cur, q)
	id := r.order[0]
	now := time.Now()
	r.qualifications[youtubeQualification{k.Network, k.Profile, id, k.HintOnly}] = now.Add(youtubeLearnTTL)
	r.completeCDNQualification(k, id, now)
	peer := c.relayUsage().beginVideo(videoPerformance{Port: q.Port, Network: cur.network, Profile: cur.profile.ID, Domain: q.Host, Started: now})
	c.relayUsage().mu.Lock()
	c.relayUsage().videoIO(peer, 100, cdnStrongBytes+1, now)
	c.relayUsage().mu.Unlock()
	c.relayUsage().videoClosed(peer, false) // recent relay survives the handoff to its successor
	open := func(ctx context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action != flowpolicy.DirectPlus {
			t.Error("unexpected relay/direct route", plan.Policy)
		}
		opens.Add(1)
		// Another connection may update the cache while this upstream opens.
		r.takeTrial(k, time.Now(), relaySiblingEvidence{AgeMS: 99999, Reason: "CONCURRENT_DENIED_CHECK"})
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	raw, _, e := c.openBrowserPlan(context.Background(), cur, q, p, open)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	secure := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	defer secure.Close()
	secure.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(secure)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", "https://"+q.Host+"/media", nil)
		if e = req.Write(secure); e != nil {
			t.Fatal(e)
		}
		response, e := http.ReadResponse(reader, req)
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			if len(body) != 5*256*1024 || r.selection.TrialSuccesses != 1 || r.selection.StrongPromotions != 1 || r.selection.DataTrials != 1 || r.trialActive {
				t.Fatal("running success not recorded", r.snapshot())
			}
			if len(r.trials) == 0 || r.trials[0].Sibling.AgeMS == 99999 {
				t.Fatal("trial lost original admission evidence", r.trials)
			}
			if stage, strategy := r.choose(k, time.Now()); stage != "LOCAL" || strategy != id {
				t.Fatal(stage, strategy)
			}
			other := k
			other.Domain = "googlevideo:sn-next"
			r.completeCDNQualification(other, id, time.Now())
			if _, ok := r.takeTrial(other, time.Now(), testSibling(true)); !ok {
				t.Fatal("live healthy flow holds global slot")
			}
		} else if string(body) != "same established TLS" {
			t.Fatal("TLS stream replaced")
		}
	}
	if opens.Load() != 1 {
		t.Fatal("socket/stream replacement", opens.Load())
	}
}
func feedCompletedBurst(m *youtubeMeter, now time.Time) {
	feedSustainedWire(m, now)
	// The whole response arrived in under a second, then keep-alive idles.
	m.firstApplicationRX = now.Add(-9 * time.Second)
	m.lastReply = now.Add(-8 * time.Second)
	m.lastClientWrite = now.Add(-9500 * time.Millisecond)
	m.rxAtLastWrite = 6000
}
func TestCompletedFastCDNBurstPromotesAfterQuietWithoutPendingRequest(t *testing.T) {
	m, r, k, id := trialMeterFixture(t, localstrategy.TCPTrace{ClientRetransmits: 7}, io.EOF)
	now := time.Now()
	feedCompletedBurst(m, now)
	m.maybePromoteTrial(now)
	if !m.promoted || r.trialActive || r.selection.StrongPromotions != 1 || r.selection.BurstPromotions != 1 {
		t.Fatal(r.snapshot())
	}
	if v := r.cache[k]; v.Stage != "LOCAL" || v.Strategy != id || !v.Confirmed || v.Reason != "SUSTAINED_CDN_BURST_COMPLETE_PROMOTED" {
		t.Fatal(v)
	}
	if r.records[1].Reason != "SUSTAINED_CDN_BURST_COMPLETE_PROMOTED" {
		t.Fatal(r.records[1])
	}
	m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED")
	if r.cache[k].Stage != "RELAY" || r.selection.PostPromotionFailures != 1 {
		t.Fatal("late failure after burst promotion hidden", r.snapshot())
	}
}
func TestCDNBurstIsNotProofWhenRequestPendingOrQuietTooShort(t *testing.T) {
	for _, variant := range []string{"short-quiet", "pending-write", "small-after-last-request", "small", "rst", "half-closed", "failed", "uncommitted"} {
		t.Run(variant, func(t *testing.T) {
			trace := localstrategy.TCPTrace{}
			if variant == "rst" {
				trace.RemoteRST = 1
			}
			m, r, _, _ := trialMeterFixture(t, trace, io.EOF)
			now := time.Now()
			feedCompletedBurst(m, now)
			switch variant {
			case "short-quiet":
				m.lastReply = now.Add(-cdnBurstQuiet + time.Second)
				m.lastClientWrite = m.lastReply.Add(-time.Second)
			case "pending-write":
				m.lastClientWrite = m.lastReply.Add(time.Millisecond)
			case "small-after-last-request":
				// A later request got only a short answer: earlier bytes do not count.
				m.rxAtLastWrite = m.rx - 4096
			case "small":
				m.rx = 65000
			case "half-closed":
				m.halfClosed = true
			case "failed":
				m.failed = true
			case "uncommitted":
				m.applied = false
			}
			m.maybePromoteTrial(now)
			if m.promoted || r.selection.TrialSuccesses != 0 || r.selection.BurstPromotions != 0 {
				t.Fatal("false burst proof", variant)
			}
		})
	}
}

type quietTimeoutError struct{}

func (quietTimeoutError) Error() string   { return "i/o timeout" }
func (quietTimeoutError) Timeout() bool   { return true }
func (quietTimeoutError) Temporary() bool { return true }

func TestQuietReadTimeoutEvaluatesCompletedBurstWithoutClosingStream(t *testing.T) {
	m, r, k, _ := trialMeterFixture(t, localstrategy.TCPTrace{}, quietTimeoutError{})
	feedCompletedBurst(m, time.Now())
	if n, e := m.Read(make([]byte, 16)); n != 0 || !isYoutubeTimeout(e) {
		t.Fatal(n, e)
	}
	if !m.promoted || m.closing || r.cache[k].Stage != "LOCAL" || r.trialActive {
		t.Fatal("idle keep-alive after a completed burst kept the trial slot", r.snapshot())
	}
}
