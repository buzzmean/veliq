package controlplane

// This opt-in, loopback-only fixture is compiled exclusively by go test. It
// serves the real cabinet API and an isolated PostgreSQL schema. Only mail and
// the external payment provider are emulated; no production credentials load.
import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/enrollment"
)

func TestStagingBrowserAcceptanceServer(t *testing.T) {
	dir := os.Getenv("VELIQ_STAGING_BROWSER_DIR")
	if dir == "" {
		t.Skip("opt-in isolated browser acceptance server")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	api, store, mail := accountAPI(t, true)
	api.Settings.Plans[0].PricePerSeatRub = 399
	api.Settings.Plans[1].PricePerSeatRub = 299
	api.Settings.PersonalTrials = true
	api.Settings.PersonalFirstPurchase = true
	api.Settings.PersonalOptimizationLeases = true
	api.Settings.ClubVerificationToken = strings.Repeat("fixture-only-operator-", 2)
	campaign, _, err := store.CreatePromotion(context.Background(), "club-launch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec(context.Background(), "UPDATE promotions SET enabled=true WHERE id=$1", campaign); err != nil {
		t.Fatal(err)
	}
	provider := newPersonalProviderEmulator(t, "", nil)
	api.Settings.Payments = provider.provider()
	var gate sync.RWMutex
	var machineSequence atomic.Uint64
	machineSequence.Store(uint64(time.Now().UnixNano()))
	website, err := filepath.Abs("../../website")
	if err != nil {
		t.Fatal(err)
	}
	static := http.FileServer(http.Dir(website))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/__fixture/") {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/__fixture/code":
				email := strings.ToLower(r.URL.Query().Get("email"))
				if r.Method != "GET" || !strings.HasSuffix(email, "@example.test") {
					http.Error(w, "fixture address required", 400)
					return
				}
				mail.mu.Lock()
				code := mail.sent[email]
				mail.mu.Unlock()
				if code == "" {
					http.Error(w, "not sent", 404)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
			case "/__fixture/state":
				email := strings.ToLower(r.URL.Query().Get("email"))
				if r.Method != "GET" || !strings.HasSuffix(email, "@example.test") {
					http.Error(w, "fixture address required", 400)
					return
				}
				var total, activated, paid int
				if err := store.DB.QueryRow(r.Context(), `SELECT count(*), count(s.trial_until), count(s.paid_until) FROM subscriptions s JOIN accounts a ON a.id=s.account_id WHERE a.email=$1`, email).Scan(&total, &activated, &paid); err != nil {
					http.Error(w, "state query", 500)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]int{"subscriptions": total, "activated_trials": activated, "paid_subscriptions": paid})
			case "/__fixture/config":
				if r.Method != "POST" {
					w.WriteHeader(405)
					return
				}
				var input struct {
					Enabled bool `json:"enabled"`
				}
				if json.NewDecoder(r.Body).Decode(&input) != nil {
					w.WriteHeader(400)
					return
				}
				gate.Lock()
				api.Settings.PersonalTrials = input.Enabled
				api.Settings.PersonalFirstPurchase = input.Enabled
				gate.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": input.Enabled})
			case "/__fixture/seed-personal-bindings":
				if r.Method != "POST" {
					w.WriteHeader(405)
					return
				}
				var input struct {
					Email string `json:"email"`
					Count int    `json:"count"`
				}
				if json.NewDecoder(r.Body).Decode(&input) != nil || input.Count != 3 || !strings.HasSuffix(input.Email, "@example.test") {
					w.WriteHeader(400)
					return
				}
				cookie, err := r.Cookie(sessionCookie)
				if err != nil {
					w.WriteHeader(401)
					return
				}
				account, err := store.SessionAccount(r.Context(), cookie.Value, time.Now())
				if err != nil || account.Email != input.Email {
					w.WriteHeader(403)
					return
				}
				var sub string
				if err = store.DB.QueryRow(r.Context(), "SELECT id FROM subscriptions WHERE account_id=$1 AND personal_optimization_lease_stage AND kind='player' AND seats=1", account.ID).Scan(&sub); err != nil {
					http.Error(w, "marked trial required", 409)
					return
				}
				gate.RLock()
				defer gate.RUnlock()
				invoke := func(path string, value any) bool {
					raw, _ := json.Marshal(value)
					request := httptest.NewRequest("POST", path, bytes.NewReader(raw))
					request.Header.Set("Content-Type", "application/json")
					request.Header.Set("Origin", api.Settings.AccountOrigin)
					request.AddCookie(cookie)
					request.RemoteAddr = "192.0.2.77:49152"
					reply := httptest.NewRecorder()
					api.Handler().ServeHTTP(reply, request)
					return reply.Code == 200 || reply.Code == 201
				}
				for range input.Count {
					link, request, key := newLinkRequest(t, "device", fmt.Sprintf("%064x", machineSequence.Add(1)))
					link.PersonalOptimizationLeaseV1 = true
					request, err = link.Request("Stage browser PC", request.Device, key, time.Now())
					if err != nil || !invoke("/api/v1/enroll/device/start", request) || !invoke("/api/v1/account/device-links/"+link.ID+"/approve", map[string]string{"subscription_id": sub}) || !invoke("/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: link.ID, Secret: link.Secret, PersonalOptimizationLeaseV1: true}) {
						http.Error(w, "fixture enrollment failed", 500)
						return
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]int{"bound": input.Count})
			case "/__fixture/provider-confirm":
				if r.Method != "POST" {
					w.WriteHeader(405)
					return
				}
				var input struct {
					ID     string `json:"id"`
					Status string `json:"status"`
				}
				if json.NewDecoder(r.Body).Decode(&input) != nil || !strings.HasPrefix(input.ID, "personal-fixture-tx-") || (input.Status != "CONFIRMED" && input.Status != "CANCELED") {
					w.WriteHeader(400)
					return
				}
				provider.mu.Lock()
				record, ok := provider.records[input.ID]
				if ok {
					record.Status = input.Status
					provider.records[input.ID] = record
				}
				provider.mu.Unlock()
				if !ok {
					w.WriteHeader(404)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			default:
				w.WriteHeader(404)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			gate.RLock()
			defer gate.RUnlock()
			api.Handler().ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" {
			r.URL.Path = "/index.html"
		} else if filepath.Ext(r.URL.Path) == "" {
			r.URL.Path += ".html"
		}
		static.ServeHTTP(w, r)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	server.Listener, err = net.Listen("tcp", "127.0.0.1:18327")
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	api.Settings.AccountOrigin = server.URL
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err = os.WriteFile(filepath.Join(dir, "fixture-cert.pem"), cert, 0600); err != nil {
		t.Fatal(err)
	}
	ready, _ := json.Marshal(map[string]any{"url": server.URL, "isolated_postgresql": true, "mail": "local-only", "payments": "loopback emulator", "production_touched": false})
	if err = os.WriteFile(filepath.Join(dir, "ready.json"), ready, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("isolated HTTPS staging ready", server.URL)
	deadline := time.Now().Add(45 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(filepath.Join(dir, "stop")); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err = store.DB.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}
