package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/localcatalog"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCatalogPublicSignedAndAdminAtomicUpdateWithoutDBMutation(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"fixture": pub}
	path := filepath.Join(t.TempDir(), "catalog.json")
	api := &API{Settings: Settings{KeyID: "fixture", SigningKey: key, AdminToken: strings.Repeat("x", 32), LocalCatalogFile: path}}
	call := func(method string, raw []byte, admin bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/local/catalog", bytes.NewReader(raw))
		if admin {
			r.Header.Set("Authorization", "Bearer "+api.Settings.AdminToken)
		}
		w := httptest.NewRecorder()
		api.localCatalog(w, r)
		return w
	}
	w := call("GET", nil, false)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if _, err := localcatalog.Validate(keys, w.Body.Bytes(), time.Now()); err != nil {
		t.Fatal(err)
	}
	input := localCatalogRelease{Version: 3, Catalog: localstrategy.BundledCatalog()}
	input.Catalog.Reviewed = "2026-10-24"
	raw, _ := json.Marshal(input)
	if w = call("PUT", raw, false); w.Code != 401 {
		t.Fatal("public publication accepted", w.Code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unauthorized write")
	}
	if w = call("PUT", raw, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	doc, err := localcatalog.Validate(keys, w.Body.Bytes(), time.Now())
	if err != nil || doc.Version != 3 {
		t.Fatal("publication signature", err)
	}
	before, _ := os.ReadFile(path)
	if w = call("PUT", raw, true); w.Code != 400 {
		t.Fatal("non-monotonic update", w.Code)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected update changed release")
	}
	api.Settings.LocalCatalogFile = ""
	if w = call("PUT", raw, true); w.Code != 503 {
		t.Fatal("ephemeral update accepted")
	}
	// Store intentionally nil: catalog publication cannot mutate devices/nonces/revocations.
	if api.Store != nil {
		t.Fatal("DB accessed")
	}
}
