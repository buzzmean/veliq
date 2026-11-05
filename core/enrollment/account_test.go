package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"strings"
	"testing"
	"time"
)

func TestDeviceLinkSignatureBindsDestinationAndPrivateCredential(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	id := strings.Repeat("a", 32)
	device, e := NewRequest(id, strings.Repeat("b", 64), key)
	if e != nil {
		t.Fatal(e)
	}
	l, e := NewDeviceLink("device")
	if e != nil {
		t.Fatal(e)
	}
	q, e := l.Request("Lab PC", device, key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"id", "secret", "machine", "name", "csr", "time", "mode", "signature"} {
		t.Run(kind, func(t *testing.T) {
			bad := q
			switch kind {
			case "id":
				bad.ID = strings.Repeat("c", 32)
			case "secret":
				next, _ := NewDeviceLink("device")
				bad.Secret = next.Secret
			case "machine":
				bad.Device.MachineHash = strings.Repeat("d", 64)
			case "name":
				bad.Name = "Other PC"
			case "csr":
				bad.Device.CSR += "x"
			case "time":
				bad.IssuedAt = time.Now().Add(-2 * time.Minute).Unix()
			case "mode":
				bad.Mode = "image"
			case "signature":
				bad.Signature = "invalid"
			}
			if _, e := bad.Validate(time.Now()); e == nil {
				t.Fatal("tampered binding accepted", kind)
			}
		})
	}
}
func TestImageApprovalNeedsNoClonedDeviceIdentity(t *testing.T) {
	l, e := NewDeviceLink("image")
	if e != nil {
		t.Fatal(e)
	}
	q, e := l.Request("Clean club image", freshpc.Request{}, nil, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if q.Device.DeviceID != "" || q.Device.CSR != "" || q.BootstrapHash == "" || q.Signature != "" {
		t.Fatal("image must not contain a device key/CSR")
	}
	if l.Secret == l.BootstrapSecret {
		t.Fatal("browser and boot credentials must be independent")
	}
	q.Device.DeviceID = strings.Repeat("a", 32)
	if _, e = q.Validate(time.Now()); e == nil {
		t.Fatal("image approval accepted cloned device identity")
	}
}
