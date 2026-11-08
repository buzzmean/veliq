//go:build windows

package clientservice

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/buzzmean/neexitlag/core/security"
)

// Exercises the unchanged updater downloader and detached Windows launcher.
// Only the metadata origin is a loopback fixture; the real production signature
// and exact manually accepted EXE are verified before the launcher is called.
func TestRelease690SystemUpdater(t *testing.T) {
	if os.Getenv("VELIQ_RELEASE_ACCEPTANCE") != "DISPOSABLE_ACTIONS_690" {
		t.Skip("explicit disposable Actions test only")
	}
	dir := os.Getenv("VELIQ_RELEASE_FIXTURE")
	setup := filepath.Join(dir, "VELIQ-Setup.exe")
	signed := filepath.Join(dir, "veliq-release.json")
	pub, err := security.DecodePublicKey("cLseViv0uB-BH-kYak_yOypqqkX2BIdfZSzfBN1k2QQ")
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			json.NewEncoder(w).Encode(map[string]any{"assets": []map[string]string{{"name": "veliq-release.json", "browser_download_url": srv.URL + "/manifest"}, {"name": "VELIQ-Setup.exe", "browser_download_url": srv.URL + "/setup"}}})
		case "/manifest":
			http.ServeFile(w, r, signed)
		case "/setup":
			http.ServeFile(w, r, setup)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	previous := BuildSequence
	BuildSequence = "682"
	defer func() { BuildSequence = previous }()
	// Use the actual production directory and actual detached launch function.
	updater := newUpdater(map[string]ed25519.PublicKey{"vps-1": pub}, filepath.Join(os.Getenv("ProgramData"), "VELIQ"), launchUpdateSetup)
	updater.api = srv.URL + "/latest"
	m, _, err := updater.latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m.Build != 690 || m.Commit != "caa04648af00d0027f3441067f9febbd31f9b19d" || m.SetupSHA256 != "1552bd2bcfc4e25e546116ee16c93387f334ab4dc1d787d7a5b6f63a381bea8e" || m.SetupSize != 56993765 {
		t.Fatal("release manifest differs from manually accepted candidate")
	}
	if ok, err := fileMatches(setup, m); !ok || err != nil {
		t.Fatal("fixture EXE mismatch", err)
	}
	updater.check(context.Background())
	status := updater.snapshot()
	if status.State != "INSTALLING" || status.Available != 690 {
		t.Fatalf("updater did not launch: %+v", status)
	}
	downloaded := filepath.Join(updater.dir, "updates", "VELIQ-Setup-690.exe")
	if ok, err := fileMatches(downloaded, m); !ok || err != nil {
		t.Fatal("downloaded EXE mismatch", err)
	}
	t.Log("RELEASE_690_UPDATER_SIGNATURE_DOWNLOAD_DETACHED_SYSTEM_LAUNCH_PASS current=682 available=690")
}
