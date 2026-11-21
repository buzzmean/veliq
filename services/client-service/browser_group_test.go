package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"net"
	"testing"
	"time"
)

func TestBrowserGroupFirstStallSteersAllMembersOnlyOnSameNetworkProfilePort(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "www.youtube.com", Port: 443, Secure: true}
	members := []string{"youtube.com", "www.youtube.com", "rr1---sn-any.googlevideo.com", "i.ytimg.com", "yt3.ggpht.com", "foo.ggpht.com", "wide-youtube.l.google.com", "youtubei.googleapis.com"}
	for _, host := range members {
		request := q
		request.Host = host
		if _, ok := c.steerTimedOutOrigin(boundedDirectPlan(), cur, request, time.Now()); ok {
			t.Fatal("unconfirmed family steered", host)
		}
	}
	c.recordBrowserStall(cur, q, boundedDirectPlan())
	for _, host := range members {
		request := q
		request.Host = host
		got, ok := c.steerTimedOutOrigin(boundedDirectPlan(), cur, request, time.Now())
		if !ok || got.Policy.Action != flowpolicy.RelayRequired || got.Policy.Fallback != flowpolicy.Required {
			t.Fatal(host, got)
		}
	}
	for _, host := range []string{"www.google.com", "play.google.com", "googlevideo.com.attacker.example", "notyoutube.com", "other.googleusercontent.com", "chatgpt.com"} {
		request := q
		request.Host = host
		if _, ok := c.steerTimedOutOrigin(boundedDirectPlan(), cur, request, time.Now()); ok {
			t.Fatal("cross-family/protected contamination", host)
		}
	}
	for _, change := range []string{"network", "profile", "port"} {
		other, request := cur, q
		switch change {
		case "network":
			other.network = "different"
		case "profile":
			other.profile.ID = "another-browser"
		case "port":
			request.Port = 80
		}
		if _, ok := c.steerTimedOutOrigin(boundedDirectPlan(), other, request, time.Now()); ok {
			t.Fatal("scope leaked", change)
		}
	}
	key := c.directTimeoutKey(cur, q)
	if c.browser.directTimeouts.ProbeHost(key) != "www.youtube.com" {
		t.Fatal("failed witness missing")
	}
	c.browser.directTimeouts.SetProbeHost(key, "www.google.com")
	if c.browser.directTimeouts.ProbeHost(key) != "www.youtube.com" {
		t.Fatal("foreign host replaced witness")
	}
	if stats := c.browser.directTimeouts.Stats(); stats.ActiveOrigins != 1 || stats.Stalls != 1 || stats.Top[0].Group != "youtube-media" {
		t.Fatal(stats)
	}
}

func TestBrowserCachedGroupRechecksStalePlanBeforeDialAndNeverDirectOnRelayFailure(t *testing.T) {
	c, cur := timeoutFixture(t)
	source := browserproxy.Request{Host: "www.youtube.com", Port: 443, Secure: true}
	p := boundedDirectPlan() // Planned BEFORE the family stall.
	c.recordBrowserStall(cur, source, p)
	q := source
	q.Host = "new-edge.googlevideo.com"
	calls := 0
	_, actual, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		calls++
		if p.Policy.Action != flowpolicy.RelayRequired || p.Policy.Fallback != flowpolicy.Required || p.DirectAttempts != 0 {
			t.Fatal("DIRECT used from stale plan", p)
		}
		return nil, errors.New("relay unavailable")
	})
	if err == nil || calls != 1 || actual.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal(calls, actual, err)
	}
	// Ordinary cached origins also bypass previously learned DIRECT without
	// affecting a different domain, and DNS/53 remains excluded.
	ordinary := source
	ordinary.Host = "ordinary.example"
	c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(cur, ordinary), time.Now())
	c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(cur, ordinary), time.Now())
	_, _, _ = c.openBrowserPlan(context.Background(), cur, ordinary, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		if p.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal("cached ordinary origin ignored", p)
		}
		return nil, errors.New("test")
	})
	source.Port = 53
	c.browser.directTimeouts.RecordOriginStall(c.directTimeoutKey(cur, source), time.Now())
	if _, ok := c.steerTimedOutOrigin(p, cur, source, time.Now()); ok {
		t.Fatal("DNS steered to relay")
	}
}

func TestBrowserGroupDoesNotExpandVerifiedLocalStrategyDomains(t *testing.T) {
	if !youtubeRelayDomain("foo.ggpht.com") || youtubeDomain("foo.ggpht.com") {
		t.Fatal("relay grouping changed DIRECT+ eligibility")
	}
	if youtubeRelayDomain("www.google.com") || youtubeRelayDomain("ggpht.com.attacker.example") {
		t.Fatal("generic Google/foreign domain grouped")
	}
}
