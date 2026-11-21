package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/enrollment"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestActivationCodeStoredPrivatelyAndNeverInStatusOrErrors(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	c.activation.configured = true
	c.activation.manifest = Manifest{DeviceIdentityFile: filepath.Join(dir, "identity.json"), StateDirectory: dir}
	c.activation.wake = make(chan struct{}, 1)
	code, e := enrollment.NewCode()
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"code": code, "stage_for_boot": true})
	result, e := c.Handle(context.Background(), "activation.set", body)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), code) {
		t.Fatal("code leaked in status")
	}
	saved, e := readActivation(c.activation.manifest)
	if e != nil || saved.Code != code || !saved.Pending || !c.activation.paused {
		t.Fatal("not privately staged", e)
	}
	st, e := os.Stat(pendingActivationFile(c.activation.manifest))
	if e != nil || runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		t.Fatal("file ACL/mode", e)
	}
	for _, method := range []string{"activation.status", "activation.set"} {
		_, e = c.Handle(context.Background(), method, []byte(`{"code":"DO_NOT_LOG_THIS_CODE"}`))
		if e != nil && strings.Contains(e.Error(), "DO_NOT_LOG") {
			t.Fatal("secret in error")
		}
	}
}
func TestActivationInvalidPinRefusesBeforeHardwareOrNetwork(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	m := Manifest{CAFile: filepath.Join(t.TempDir(), "ca.pem")}
	_, _, e := c.activationAttempt(context.Background(), m, activationRecord{})
	if e == nil || e.Error() != "ACTIVATION_TRUST_NOT_CONFIGURED" {
		t.Fatal("untrusted enrollment allowed", e)
	}
}
func TestActivationSafeErrorNeverReflectsCredential(t *testing.T) {
	if got := activationSafeError(os.ErrPermission); got != "ACTIVATION_UNAVAILABLE" {
		t.Fatal("unsafe OS error")
	}
}

func TestActivationPendingChangePreservesWorkingCodeAndRevocationStatus(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	c.activation.configured = true
	c.activation.manifest = Manifest{DeviceIdentityFile: filepath.Join(dir, "identity.json"), StateDirectory: dir}
	c.activation.wake = make(chan struct{}, 1)
	old, _ := enrollment.NewCode()
	next, _ := enrollment.NewCode()
	r := activationRecord{Code: old, RequestID: strings.Repeat("a", 32)}
	raw, _ := json.Marshal(r)
	if e := protectedActivationWrite(activationFile(c.activation.manifest), raw); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"code": next})
	if _, e := c.Handle(context.Background(), "activation.set", body); e != nil {
		t.Fatal(e)
	}
	saved, e := readActivationRecord(activationFile(c.activation.manifest))
	if e != nil || saved.Code != old {
		t.Fatal("working code replaced before successful enrollment", e)
	}
	pending, e := readActivation(c.activation.manifest)
	if e != nil || pending.Code != next {
		t.Fatal("pending code missing", e)
	}
	c.activation.status.State = "ACTIVATED"
	c.activation.revoked = true
	if status := c.activationStatus(); status.State != "ACTIVATION_ERROR" || status.Error != "DEVICE_REVOKED" {
		t.Fatal("revoked device displayed as activated", status)
	}
}
