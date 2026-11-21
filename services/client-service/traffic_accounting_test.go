package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/traffic"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrafficReadOnlyIPCBrowserReasonsAndClubPermission(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	c.clubMode.Store(true)
	if _, e := c.HandleOwnerIPC(context.Background(), "traffic.status", nil); e != nil {
		t.Fatal(e)
	}
	c.accountRelayTraffic(routing.Flow{ApplicationID: "chrome", OriginDomain: q.Host, OriginService: "youtube-media", OriginReason: "LOCAL_HEALTH_NOT_CONFIRMED", Route: routing.Route{RelayID: "VPS-01"}}, 1, 2000)
	s := c.traffic.Snapshot(time.Now())
	if s.DayTotal.Received != 2000 || len(s.Days) != 1 || s.Days[0].Reason != "LOCAL_HEALTH_NOT_CONFIRMED" {
		t.Fatal(s)
	}
	p.Policy.Source = youtubeLadderSource
	p.Policy.Action = "RELAY_REQUIRED"
	if c.browserTrafficReason(cur, q, p) != "LOCAL_HEALTH_NOT_CONFIRMED" {
		t.Fatal("relay reason not explained")
	}
	if _, e := c.HandleOwnerIPC(context.Background(), "traffic.set", nil); e == nil {
		t.Fatal("guest quota mutation")
	}
}
func TestTrafficRemoteLegacyCPDoesNotInventQuota(t *testing.T) {
	for _, status := range []int{200, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c := New(context.Background())
			defer c.Close()
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				if status == 200 {
					now := time.Now()
					raw, _ := security.Sign(traffic.Domain, "k", key, traffic.Document{GeneratedAt: now, ExpiresAt: now.Add(time.Minute), Relays: []traffic.MonthRow{{Relay: "VPS-PRIMARY", Month: now.UTC().Format("2006-01"), From: now, Last: traffic.Observation{At: now}, Bytes: 123, Partial: true}}})
					w.Write(raw)
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				c.runRemoteTraffic(ctx, &controlclient.Client{BaseURL: server.URL, HTTP: server.Client()}, map[string]ed25519.PublicKey{"k": pub})
			}()
			defer func() { cancel(); <-done }()
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				c.remoteTraffic.mu.Lock()
				checked := !c.remoteTraffic.checked.IsZero()
				c.remoteTraffic.mu.Unlock()
				if checked {
					break
				}
				time.Sleep(time.Millisecond)
			}
			c.remoteTraffic.mu.Lock()
			state := c.remoteTraffic.state
			rows := append([]traffic.MonthRow(nil), c.remoteTraffic.rows...)
			c.remoteTraffic.mu.Unlock()
			if status == 404 && (len(rows) != 0 || state != "SERVER_TRAFFIC_UNAVAILABLE_OR_UNSIGNED") {
				t.Fatal(state, rows)
			}
			if status == 200 && (len(rows) != 1 || rows[0].Bytes != 123 || state != "SIGNED_SERVER_NIC_TRAFFIC") {
				t.Fatal(state, rows)
			}
		})
	}
}
