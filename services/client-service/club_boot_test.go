package clientservice

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClubImageCannotEnrollUntilBootTaskArmsIt(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{ClubImage: true, ControlPlaneURL: "https://127.0.0.1:1", DeviceIdentityFile: filepath.Join(dir, "identity.json"), DeviceCertificate: filepath.Join(dir, "device.pem"), StateDirectory: filepath.Join(dir, "state"), TokenFile: filepath.Join(dir, "ipc.token")}
	c := New(context.Background())
	defer c.Close()
	if !c.ConfigureActivation(m) || c.activationStatus().State != "CLUB_IMAGE_STAGED" || c.activationNetworkAllowed() {
		t.Fatal("unsealed image activated", c.activationStatus())
	}
	if _, err := os.Stat(m.DeviceIdentityFile); !os.IsNotExist(err) {
		t.Fatal("image generated key")
	}
	marker := filepath.Join(dir, "club-boot-ready.json")
	os.WriteFile(marker, []byte(`{"version":1,"source":"FOREIGN"}`), 0600)
	if clubBootReady(m) {
		t.Fatal("foreign flag armed activation")
	}
	os.WriteFile(marker, []byte(`{"version":1,"source":"VELIQ_CLUB_BOOT","created_at":"fixture"}`), 0600)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.activation.mu.Lock()
		paused := c.activation.paused
		c.activation.mu.Unlock()
		if !paused {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("valid startup flag failed to wake worker")
}
