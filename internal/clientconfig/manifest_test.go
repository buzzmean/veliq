package clientconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLegacyActivationManifestDefaultsAreSharedAndSideEffectFree(t *testing.T) {
	root := t.TempDir()
	input := Manifest{StateDirectory: filepath.Join(root, "state"), TokenFile: filepath.Join(root, "ipc.token"), DeviceIdentityFile: filepath.Join(root, "identity.json"), ControlPlaneURL: "https://192.0.2.10:8443", OwnerSID: "test-owner"}
	path := filepath.Join(root, "service.json")
	raw, _ := json.Marshal(input)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProbeTokenFile != filepath.Join(root, "probe.token") || got.ProbeTarget != "192.0.2.10:40000" {
		t.Fatal("missing runtime echo defaults")
	}
	if !reflect.DeepEqual(Normalize(got), got) || got.OwnerSID != input.OwnerSID {
		t.Fatal("non-idempotent or identity changed")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("manifest modified")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Fatal("normalization created runtime files")
	}
}
func TestExplicitProbeSettingsAndUnconfiguredManifestArePreserved(t *testing.T) {
	m := Manifest{ProbeTokenFile: "explicit-probe", ProbeTarget: "192.0.2.20:40001", TCPProbeTarget: "192.0.2.30:40002", ControlPlaneURL: "https://192.0.2.10:8443"}
	if !reflect.DeepEqual(m, Normalize(m)) {
		t.Fatal("explicit probe settings changed")
	}
	if !reflect.DeepEqual(Manifest{}, Normalize(Manifest{})) {
		t.Fatal("empty manifest got invented credentials")
	}
	for _, u := range []string{"https://192.0.2.10:8443", "https://[2001:db8::1]:8443"} {
		if Normalize(Manifest{ControlPlaneURL: u}).ProbeTarget == "" {
			t.Fatal("CP host default absent")
		}
	}
}
func TestManifestReadRejectsUnknownAndRelativePaths(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "service.json")
	for _, raw := range []string{`{"token_file":"relative","state_directory":"relative"}`, `{"unexpected_secret":true}`} {
		os.WriteFile(path, []byte(raw), 0600)
		if _, err := Load(path); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
}
