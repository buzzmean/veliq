package clientservice

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/enrollment"
)

func TestAccountRealBrowserRegistrationToDeviceBinding(t *testing.T) {
	if os.Getenv("VELIQ_TEST_ACCOUNT_BROWSER") != "1" {
		t.Skip("isolated PostgreSQL, Chromium, NSS certutil and Python Playwright required")
	}
	if runtime.GOOS != "linux" {
		t.Skip("NSS browser fixture is Linux-only; native WPF/service are separate gates")
	}
	for _, kind := range []string{"player", "club"} {
		t.Run(kind, func(t *testing.T) {
			f := newAccountFixture(t)
			m := f.manifest(t)
			c := New(context.Background())
			t.Cleanup(c.Close)
			c.activation.hardware = accountFixtureHardware
			credential, e := enrollment.NewDeviceLink("device")
			if e != nil {
				t.Fatal(e)
			}
			token := credential.Secret
			root := filepath.Clean(filepath.Join("..", ".."))
			mux := http.NewServeMux()
			mux.Handle("/api/", f.api.Handler())
			mux.HandleFunc("/_fixture/", func(w http.ResponseWriter, r *http.Request) {
				if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Veliq-Fixture")), []byte(token)) != 1 {
					http.Error(w, "fixture authorization", 403)
					return
				}
				switch r.URL.Path {
				case "/_fixture/inbox":
					f.mail.mu.Lock()
					code := f.mail.code
					f.mail.mu.Unlock()
					json.NewEncoder(w).Encode(map[string]string{"code": code})
				case "/_fixture/credit":
					var q struct {
						Subscription string `json:"subscription_id"`
					}
					if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&q) != nil || !enrollment.AccountLinkID(q.Subscription) {
						http.Error(w, "fixture input", 400)
						return
					}
					if _, e := f.store.DB.Exec(r.Context(), "UPDATE subscriptions SET paid_until=now()+interval '30 days' WHERE id=$1", q.Subscription); e != nil {
						http.Error(w, "fixture database", 503)
						return
					}
					w.Write([]byte(`{}`))
				case "/_fixture/client":
					s := c.accountConnectionStatus()
					r, e := readActivation(m)
					json.NewEncoder(w).Encode(map[string]any{"linked": e == nil && !r.Pending && s.State == "LINKED", "has_identity": validActivationIdentity(m), "manual_code": e == nil && r.Code != "", "kind": s.Kind})
				default:
					http.NotFound(w, r)
				}
			})
			mux.Handle("/", http.FileServer(http.Dir(filepath.Join(root, "website"))))
			f.server.Config.Handler = mux
			c.ConfigureActivation(m)
			if _, e = c.HandleOwnerIPC(context.Background(), "account.link.start", nil); e != nil {
				t.Fatal(e)
			}
			s := waitAccountFixture(t, c, func(s accountConnectionStatus) bool { return s.State == "WAITING_FOR_BROWSER" })
			meta := map[string]string{"origin": f.server.URL, "url": s.VerificationURL, "ca_path": m.CAFile, "token": token, "kind": kind}
			raw, _ := json.Marshal(meta)
			path := filepath.Join(t.TempDir(), "fixture.json")
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "python3", filepath.Join(root, "tests/frontend/account_onboarding_smoke.py"), "--fixture", path)
			out, e := command.CombinedOutput()
			if e != nil {
				t.Log(string(out))
				t.Fatal("real browser account flow failed", e)
			}
			t.Log(string(out))
		})
	}
}
