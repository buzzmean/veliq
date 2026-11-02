//go:build windows

package clientservice

import (
	"context"
	"encoding/json"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type ownerProxySystemFixture struct{ Owner, Worker string }
type ownerProxySystemProof struct {
	System, OwnerPrimary, Restored bool
	Error                          string
}

// Opt-in test executable launched as a temporary SYSTEM service. It deliberately
// is not the production VELIQ service, has no production manifest/credentials,
// and creates no network session. WinINET itself refuses impersonation-only SID.
func TestWindowsOwnerProxySYSTEMChild(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal("fixture executable unavailable")
	}
	if filepath.Base(self) != "owner-system-child.exe" {
		t.Skip("explicit isolated SYSTEM fixture child")
	}
	root := filepath.Dir(self)
	raw, err := os.ReadFile(filepath.Join(root, "owner-system-input.json"))
	if err != nil {
		t.Fatal("fixture input unavailable")
	}
	var config ownerProxySystemFixture
	if len(raw) > 8192 || json.Unmarshal(raw, &config) != nil {
		t.Fatal("fixture input invalid")
	}
	proof := ownerProxySystemProof{}
	defer func() {
		raw, _ := json.Marshal(proof)
		_ = os.WriteFile(filepath.Join(root, "owner-system-result.json"), raw, 0600)
	}()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || u.User.Sid.String() != "S-1-5-18" {
		proof.Error = "FIXTURE_SYSTEM_REQUIRED"
		return
	}
	proof.System = true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exchange := func(q wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
		return exchangeOwnerProxyWithBinary(ctx, q, config.Worker)
	}
	original, err := exchange(wp.OwnerProxyCommand{Owner: config.Owner})
	if err != nil {
		proof.Error = err.Error()
		return
	}
	proof.OwnerPrimary = true
	if !freeOwnerProxy(original) {
		proof.Error = "FIXTURE_FOREIGN_PROXY_PRESERVED"
		return
	}
	desired := original
	desired.Flags = (desired.Flags | 1) ^ 8 // Only toggle WPAD detection in the disposable owner session.
	actual, err := exchange(wp.OwnerProxyCommand{Owner: config.Owner, Expected: &original, Desired: &desired})
	if err != nil || actual != desired {
		proof.Error = "FIXTURE_OWNER_SET_FAILED"
		return
	}
	defer func() {
		restore, err := exchange(wp.OwnerProxyCommand{Owner: config.Owner, Expected: &desired, Desired: &original})
		proof.Restored = err == nil && restore == original
		if !proof.Restored {
			proof.Error = "FIXTURE_OWNER_RESTORE_FAILED"
		}
	}()
}

func TestWindowsOwnerProxyWorkerFromSYSTEM(t *testing.T) {
	if os.Getenv("VELIQ_TEST_AUTHORITY_RUNTIME") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("disposable Actions SYSTEM owner worker fixture")
	}
	helper := os.Getenv("VELIQ_TEST_OWNER_WORKER")
	if !filepath.IsAbs(helper) {
		t.Fatal("compiled absolute service worker required")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("owner token unavailable")
	}
	root := t.TempDir()
	input, _ := json.Marshal(ownerProxySystemFixture{Owner: user.User.Sid.String(), Worker: helper})
	if err := os.WriteFile(filepath.Join(root, "owner-system-input.json"), input, 0600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	child := filepath.Join(root, "owner-system-child.exe")
	destination, err := os.OpenFile(child, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("fixture binary copy failed")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal("isolated SCM required", err)
	}
	defer manager.Disconnect()
	name := "VELIQAuthorityWorkerTest-" + strconv.Itoa(os.Getpid())
	service, err := manager.CreateService(name, child, mgr.Config{StartType: mgr.StartManual}, "-test.run=^TestWindowsOwnerProxySYSTEMChild$", "-test.v")
	if err != nil {
		t.Fatal("temporary fixture service", err)
	}
	defer service.Close()
	defer service.Delete()
	// This one-shot test process exits instead of reporting SCM readiness. The
	// expected Start error is not the proof; only its bounded JSON result counts.
	_ = service.Start()
	until := time.Now().Add(20 * time.Second)
	for time.Now().Before(until) {
		raw, err := os.ReadFile(filepath.Join(root, "owner-system-result.json"))
		if err == nil {
			var proof ownerProxySystemProof
			if json.Unmarshal(raw, &proof) != nil || !proof.System || !proof.OwnerPrimary || !proof.Restored || proof.Error != "" {
				t.Fatal("SYSTEM owner worker failed", proof.Error)
			}
			t.Log("OWNER_PROXY_SYSTEM_PROOF parent_system=true child_real_owner=true wininet_roundtrip=true full_original_restored=true")
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("SYSTEM owner worker result missing")
}
