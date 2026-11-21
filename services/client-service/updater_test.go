package clientservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/release"
	"github.com/buzzmean/neexitlag/core/security"
)

func updateFixture(t *testing.T, build uint64, signer ed25519.PrivateKey, setup []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(setup)
	signed, e := security.Sign(release.Domain, "vps-1", signer, release.Manifest{Build: build, Version: "0.4.0", Commit: "0123456789abcdef0123456789abcdef01234567", SetupSize: int64(len(setup)), SetupSHA256: hex.EncodeToString(sum[:])})
	if e != nil {
		t.Fatal(e)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"assets":[{"name":%q,"browser_download_url":%q},{"name":%q,"browser_download_url":%q}]}`, release.ManifestAsset, srv.URL+"/m", release.SetupAsset, srv.URL+"/s")
		case "/m":
			w.Write(signed)
		case "/s":
			http.ServeContent(w, r, "VELIQ-Setup.exe", time.Time{}, bytes.NewReader(setup))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestUpdater(t *testing.T, srv *httptest.Server, trusted ed25519.PublicKey, current string) (*updater, *[]string) {
	t.Helper()
	old := BuildSequence
	BuildSequence = current
	t.Cleanup(func() { BuildSequence = old })
	var launched []string
	u := newUpdater(map[string]ed25519.PublicKey{"vps-1": trusted}, t.TempDir(), func(p string) error { launched = append(launched, p); return nil })
	u.api = srv.URL + "/latest"
	u.http = srv.Client()
	return u, &launched
}

func TestUpdaterInstallsSignedNewerBuildOnce(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	setup := []byte("MZ fixture setup")
	u, launched := newTestUpdater(t, updateFixture(t, 120, key, setup), pub, "100")
	u.check(context.Background())
	if len(*launched) != 1 || u.snapshot().State != "INSTALLING" {
		t.Fatalf("state %+v launched %v", u.snapshot(), *launched)
	}
	if raw, _ := os.ReadFile((*launched)[0]); string(raw) != string(setup) || filepath.Base((*launched)[0]) != "VELIQ-Setup-120.exe" {
		t.Fatal("downloaded setup mismatch")
	}
	u.check(context.Background())
	if len(*launched) != 1 || u.snapshot().State != "WAITING_RETRY" {
		t.Fatalf("second check must not relaunch: %+v", u.snapshot())
	}
}

func TestUpdaterRejectsUntrustedSignatureAndOlderBuild(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	u, launched := newTestUpdater(t, updateFixture(t, 120, other, []byte("MZ evil")), pub, "100")
	u.check(context.Background())
	if len(*launched) != 0 || u.snapshot().Error != "UPDATE_SIGNATURE_INVALID" {
		t.Fatalf("untrusted manifest accepted: %+v", u.snapshot())
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	u2, launched2 := newTestUpdater(t, updateFixture(t, 90, key, []byte("MZ old")), key.Public().(ed25519.PublicKey), "100")
	u2.check(context.Background())
	if len(*launched2) != 0 || u2.snapshot().State != "UP_TO_DATE" {
		t.Fatalf("older build must not install: %+v", u2.snapshot())
	}
}

func TestUpdaterSkipsClubImageAndDeveloperBuild(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	srv := updateFixture(t, 120, key, []byte("MZ"))
	dev, launched := newTestUpdater(t, srv, key.Public().(ed25519.PublicKey), "0")
	dev.check(context.Background())
	if len(*launched) != 0 || dev.snapshot().Error != "DEVELOPER_BUILD" {
		t.Fatalf("developer build updated: %+v", dev.snapshot())
	}
	club, launched2 := newTestUpdater(t, srv, key.Public().(ed25519.PublicKey), "100")
	os.WriteFile(filepath.Join(club.dir, "club-mode.json"), []byte(`{"enabled":true}`), 0o600)
	club.check(context.Background())
	if len(*launched2) != 0 || club.snapshot().Error != "CLUB_IMAGE_MANAGED" {
		t.Fatalf("club image updated: %+v", club.snapshot())
	}
}

func TestUpdaterResumesPartialDownload(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	setup := bytes.Repeat([]byte("VELIQ-setup-fixture-"), 4096)
	u, launched := newTestUpdater(t, updateFixture(t, 130, key, setup), pub, "100")
	dir := filepath.Join(u.dir, "updates")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "VELIQ-Setup-130.exe.part"), setup[:len(setup)/2], 0o600)
	u.check(context.Background())
	if len(*launched) != 1 {
		t.Fatalf("resume failed: %+v", u.snapshot())
	}
	if raw, _ := os.ReadFile((*launched)[0]); !bytes.Equal(raw, setup) {
		t.Fatal("resumed file differs")
	}
}
