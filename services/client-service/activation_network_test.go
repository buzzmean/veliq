package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/enrollment"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type activationCaptureFixture struct {
	starts atomic.Int32
	active atomic.Bool
}

func (b *activationCaptureFixture) Start(context.Context, wp.Classifier) error {
	b.starts.Add(1)
	b.active.Store(true)
	return nil
}
func (b *activationCaptureFixture) Stop() error { b.active.Store(false); return nil }
func (b *activationCaptureFixture) Status() wp.CaptureStatus {
	return wp.CaptureStatus{Ready: b.active.Load(), Capabilities: wp.Capabilities{TCP: true, UDP: true, IPv4: true}}
}
func (*activationCaptureFixture) Traffic() (uint64, uint64) { return 0, 0 }
func TestActivationOnlyCannotStartCaptureOrPublishBrowserPolicy(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	b := &activationCaptureFixture{}
	c.Backend = b
	c.BrowserOwnerSID = "S-1-test"
	d := t.TempDir()
	if err := c.SetCustomPath(filepath.Join(d, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{ControlPlaneURL: "https://127.0.0.1:1", CAFile: filepath.Join(d, "ca.pem"), StateDirectory: d, DeviceIdentityFile: filepath.Join(d, "identity.json"), DeviceCertificate: filepath.Join(d, "device.pem")}
	if !c.ConfigureActivation(manifest) {
		t.Fatal("fresh installation bypassed managed activation")
	}
	c.Start()
	for _, method := range []string{"optimize", "browser.native.enable", "browser.prepare", "browser.start", "browser.silent.apply", "edge.prepare", "edge.silent.apply", "edge.policy"} {
		if _, err := c.Handle(context.Background(), method, []byte(`{"enabled":true}`)); err == nil || err.Error() != "ACTIVATION_REQUIRED" {
			t.Fatal("preactivation mutation reached backend", method, err)
		}
	}
	if err := c.RestoreBrowserTransport(); err != nil {
		t.Fatal(err)
	}
	c.RetrySilentBrowserPolicies()
	status := c.Snapshot()
	if status.CaptureActive || status.CapturePermitted || status.Optimizing || b.starts.Load() != 0 || status.CaptureBlockedReason != "ACTIVATION_REQUIRED" {
		t.Fatal("activation-only touched capture")
	}
	if c.browser.server != nil || c.browser.edge != nil && c.browser.edge.server != nil {
		t.Fatal("activation-only started proxy")
	}
	// The persistent code is accepted through IPC, but invalid trust/enroll still
	// cannot enable capture. No request reaches any external host.
	code, _ := enrollment.NewCode()
	raw, _ := json.Marshal(map[string]string{"code": code})
	if _, err := c.Handle(context.Background(), "activation.set", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err == nil || b.starts.Load() != 0 {
		t.Fatal("pending code enabled driver")
	}
}
func TestActivationHardwareDiagnosticsContainNoIdentifiers(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	h := enrollment.Hardware{UUID: "10203040-5060-7080-90a0-b0c0d0e0f001", BoardSerial: "Default string", MAC: "10:11:22:33:44:55"}
	c.activation.hardware = func(context.Context) (enrollment.Hardware, error) { return h, nil }
	hash, err := c.activationHardware(context.Background(), make([]byte, 32))
	if err != nil || hash == "" {
		t.Fatal(err)
	}
	status := c.activationStatus()
	if status.Hardware.BoardSerial != "PLACEHOLDER" || status.Hardware.Scheme != "V3_UUID_MAC" {
		t.Fatal("missing safe diagnostics")
	}
	raw, _ := json.Marshal(status)
	for _, secret := range []string{h.UUID, h.BoardSerial, h.MAC, hash} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("identifier in IPC")
		}
	}
	h.UUID = ""
	_, err = c.activationHardware(context.Background(), make([]byte, 32))
	if err == nil || c.activationStatus().Hardware.Reason != "HARDWARE_UUID_AND_BOARD_UNAVAILABLE" {
		t.Fatal("missing component not diagnosed")
	}
}
func TestActivationCleanupReadsJournalWithoutRestoringProxy(t *testing.T) {
	c, p, value := silentFixture(t, false)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	request, _ := json.Marshal(map[string]string{"profile_id": p.ID})
	if _, err := c.Handle(context.Background(), "browser.silent.apply", request); err != nil {
		t.Fatal(err)
	}
	saved := *value
	if saved == "" {
		t.Fatal("fixture did not publish policy")
	}
	c.activation.networkBlocked.Store(true)
	removed := 0
	c.browser.chromeRemove = func(_ string, owned []string) error {
		for _, v := range owned {
			if v == *value {
				*value = ""
				removed++
				return nil
			}
		}
		return os.ErrPermission
	}
	if err := c.CleanupOwnedBrowserPolicies(); err != nil {
		t.Fatal(err)
	}
	if removed != 1 || *value != "" || c.activationStatus().PolicyCleanup != "REMOVED_OR_ABSENT" {
		t.Fatal("owned policy survived cleanup")
	}
	// A stopped/restarted service loads only ownership metadata, no proxy listener.
	next := New(context.Background())
	defer next.Close()
	next.customPath = c.customPath
	next.BrowserOwnerSID = c.BrowserOwnerSID
	next.browser.chromeRemove = c.browser.chromeRemove
	*value = saved
	if err := next.CleanupOwnedBrowserPolicies(); err != nil {
		t.Fatal(err)
	}
	if next.browser.server != nil || *value != "" {
		t.Fatal("cleanup restored a transport")
	}
	*value = "foreign"
	if err := next.CleanupOwnedBrowserPolicies(); err == nil || *value != "foreign" {
		t.Fatal("foreign policy removed")
	}
}

func TestActivationOwnedPACIntentionalStopVersusCrash(t *testing.T) {
	for _, graceful := range []bool{false, true} {
		t.Run(map[bool]string{false: "crash-or-initialization-error", true: "intentional-stop"}[graceful], func(t *testing.T) {
			c, p, value := silentFixture(t, false)
			c.customPath = filepath.Join(t.TempDir(), "profiles.json")
			raw, _ := json.Marshal(map[string]string{"profile_id": p.ID})
			if _, err := c.Handle(context.Background(), "browser.silent.apply", raw); err != nil {
				t.Fatal(err)
			}
			c.browser.chromeRemove = func(_ string, owned []string) error {
				for _, v := range owned {
					if v == *value {
						*value = ""
						return nil
					}
				}
				return os.ErrPermission
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if graceful {
				cancel()
			}
			if err := c.CloseForHost(ctx); err != nil {
				t.Fatal(err)
			}
			if graceful && *value != "" {
				t.Fatal("stopped service left dead mandatory PAC")
			}
			if !graceful && *value == "" {
				t.Fatal("crash guard lost")
			}
		})
	}
}

func TestActivationPreauthenticationCleanupDoesNotRemoveActivatedGuard(t *testing.T) {
	c, p, value := silentFixture(t, false)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	raw, _ := json.Marshal(map[string]string{"profile_id": p.ID})
	if _, err := c.Handle(context.Background(), "browser.silent.apply", raw); err != nil {
		t.Fatal(err)
	}
	c.browser.chromeRemove = func(_ string, _ []string) error { *value = ""; return nil }
	c.activation.networkBlocked.Store(true)
	c.RetrySilentBrowserPolicies()
	if *value == "" {
		t.Fatal("CP wait removed authenticated crash guard")
	}
	c.activation.mu.Lock()
	c.activation.preactivationCleanup = true
	c.activation.mu.Unlock()
	c.RetrySilentBrowserPolicies()
	if *value != "" {
		t.Fatal("credential-less installation retained stale proxy")
	}
}
