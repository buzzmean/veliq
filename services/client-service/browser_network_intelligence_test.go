package clientservice

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"golang.org/x/net/dns/dnsmessage"
)

func TestNetworkIntelligenceDNSNegativeIsObservedWithoutChangingWireOrHints(t *testing.T) {
	c, cur := timeoutFixture(t)
	tuple := policyTuple("udp", 53)
	for _, tc := range []struct {
		rcode dnsmessage.RCode
		state string
	}{{dnsmessage.RCodeNameError, "DNS_NXDOMAIN"}, {dnsmessage.RCodeServerFailure, "DNS_SERVFAIL"}} {
		query, reply := brokerWire(t, "www.youtube.com")
		var m dnsmessage.Message
		m.Unpack(reply)
		m.Answers = nil
		m.RCode = tc.rcode
		negative, _ := m.Pack()
		out, err := c.exchangeBrowserDNS(context.Background(), cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) { return negative, nil })
		if err != nil || !bytes.Equal(out, negative) {
			t.Fatal("DNS semantics changed", err)
		}
		hints, err := browserproxy.ValidateDNSResponse(query, out)
		if err != nil || len(hints) != 0 {
			t.Fatal("negative DNS injected hints", err)
		}
		rows := c.browser.dnsWire.snapshot()["records"].([]browserDNSRecord)
		v := rows[len(rows)-1]
		if v.Network != cur.network || v.Result != tc.state || v.Diagnosis.State != tc.state || v.Diagnosis.PageVerified || v.ID == 0 {
			t.Fatal(v)
		}
	}
	query, _ := brokerWire(t, "www.youtube.com")
	_, err := c.exchangeBrowserDNS(context.Background(), cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
		return nil, context.DeadlineExceeded
	})
	if err == nil || err.Error() != "BROWSER_DNS_TRANSACTION_FAILED" {
		t.Fatal("public failure contract changed", err)
	}
	rows := c.browser.dnsWire.snapshot()["records"].([]browserDNSRecord)
	if rows[len(rows)-1].Result != "DNS_TIMEOUT" {
		t.Fatal(rows)
	}
}

func TestNetworkIntelligenceMidstreamFailureUsesExistingScopedLadder(t *testing.T) {
	c, cur, q, plan := youtubeFixture(t)
	r := c.browser.youtube
	key := youtubeScope(cur, q)
	other := key
	other.Network = "different-network"
	id := youtubeLegacyOrder[0]
	r.confirmed(key, "LOCAL", id, time.Now())
	r.confirmed(other, "LOCAL", id, time.Now())
	r.records[1] = youtubeRecord{ID: 1, Network: cur.network, Domain: q.Host, Profile: cur.profile.ID, Stage: "LOCAL", Active: true}
	r.seq = 1
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	m := &youtubeMeter{Conn: a, r: r, id: 1, label: "LOCAL:" + id, key: key, stage: "LOCAL", strategy: id, started: time.Now(), healthy: true, tx: 2000, transform: func() bool { return true }}
	monitored := browserproxy.WatchMidstream(m, 40*time.Millisecond, func() { m.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED") })
	done := make(chan struct{})
	go func() {
		defer close(done)
		hello := append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)
		wire := append(hello, append([]byte{23, 3, 3, 4, 0}, make([]byte, 1024)...)...)
		if _, e := b.Write(wire); e != nil {
			return
		}
		b.Read(make([]byte, 64))
	}()
	if _, err := monitored.Read(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, err := monitored.Write([]byte{23, 3, 3, 0, 1, 'x'}); err != nil {
		t.Fatal(err)
	}
	if _, err := monitored.Read(make([]byte, 4096)); !errors.Is(err, browserproxy.ErrDirectMidstreamStall) {
		t.Fatal("stall not observed", err)
	}
	<-done
	if stage, _ := r.choose(key, time.Now()); stage != "RELAY" {
		t.Fatal("failed LOCAL was reused", stage)
	}
	if stage, _ := r.choose(other, time.Now()); stage != "LOCAL" {
		t.Fatal("other network poisoned", stage)
	}
	rows := r.snapshot().Records
	if len(rows) != 1 || rows[0].Diagnosis.State != "UNANSWERED_REQUEST_STALL_NOT_PLAYBACK_PROOF" || rows[0].Diagnosis.PlaybackVerified {
		t.Fatal(rows)
	}
	if !c.localLadderEligible(cur, q, plan) {
		t.Fatal("invalid positive-control plan")
	}
	for _, host := range []string{"chatgpt.com", "claude.ai", "web.telegram.org", "instagram.com"} {
		q.Host = host
		if c.localLadderEligible(cur, q, plan) {
			t.Fatal("diagnostic result authorized protected LOCAL", host)
		}
	}
}
