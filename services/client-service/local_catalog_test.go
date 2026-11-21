package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/localcatalog"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/security"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCatalogBackgroundAcceptsSignedDataAndLegacyCPDoesNotAffectRoutes(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	data, _ := security.Sign(localcatalog.Domain, "fixture", key, localcatalog.Document{Version: 4, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), Catalog: localstrategy.BundledCatalog()})
	for _, status := range []int{200, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/local/catalog" {
					t.Error("unexpected endpoint")
				}
				w.WriteHeader(status)
				if status == 200 {
					w.Write(data)
				}
			}))
			defer server.Close()
			state := newClientCatalog()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				state.run(ctx, &controlclient.Client{BaseURL: server.URL}, map[string]ed25519.PublicKey{"fixture": pub}, t.TempDir())
			}()
			defer func() { cancel(); <-done }()
			deadline := time.Now().Add(3 * time.Second)
			for state.snapshot().LastCheck.IsZero() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			view := state.snapshot()
			if view.LastCheck.IsZero() {
				t.Fatal("no bounded check")
			}
			if status == 200 && (view.Version != 4 || view.Source != "SIGNED_CONTROL_PLANE") {
				t.Fatal("signed catalog not accepted", view.Source, view.Error)
			}
			if status == 404 && (view.Version != 0 || view.Source != "BUNDLED_REVIEWED") {
				t.Fatal("legacy CP broke bundled catalog")
			}
		})
	}
}

func TestClubReadOnlyCatalogAndRelayDiagnosticsDoNotGrantMutation(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.clubMode.Store(true)
	for _, method := range []string{"local.catalog", "relay.primary.status"} {
		if _, err := c.HandleOwnerIPC(context.Background(), method, nil); err != nil {
			t.Fatal(method, err)
		}
	}
	for _, method := range []string{"local.set", "settings.set", "optimize", "future.catalog.set"} {
		if _, err := c.HandleOwnerIPC(context.Background(), method, nil); err == nil || err.Error() != "CLUB_ADMIN_MANAGED" {
			t.Fatal("club mutation allowed", method, err)
		}
	}
}
