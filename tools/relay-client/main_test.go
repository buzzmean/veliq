package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMissingIdentityIsNeverCreatedOrEnrolled(t *testing.T) {
	root := t.TempDir()
	identity := filepath.Join(root, "missing.json")
	manifestPath := filepath.Join(root, "service.json")
	raw, _ := json.Marshal(manifest{DeviceIdentityFile: identity, TokenFile: filepath.Join(root, "ipc.token"), StateDirectory: root})
	os.WriteFile(manifestPath, raw, 0600)
	if _, _, e := connect(context.Background(), manifestPath, "VPS-01", "146.0.77.98:4433"); e == nil || e.Error() != "EXISTING_IDENTITY_REQUIRED" {
		t.Fatal(e)
	}
	if _, e := os.Stat(identity); !os.IsNotExist(e) {
		t.Fatal("identity created")
	}
}
