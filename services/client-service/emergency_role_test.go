package clientservice

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/buzzmean/neexitlag/core/emergency"
	"github.com/buzzmean/neexitlag/core/enrollment"
)

func TestPersonalEmergencyIsRejectedBeforePasswordOrCleanup(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	passwordRead, stopped := false, false
	manager := emergency.NewManager(emergency.New("owner", func() ([]byte, error) {
		passwordRead = true
		return nil, nil
	}), func() error { stopped = true; return nil })
	c.ConfigureEmergencyManager(manager)
	for _, method := range []string{"emergency.status", "emergency.stop", "emergency.finish"} {
		for _, handler := range []func(context.Context, string, json.RawMessage) (any, error){c.Handle, c.HandleOwnerIPC} {
			if _, err := handler(context.Background(), method, nil); err == nil || err.Error() != "EMERGENCY_CLUB_ONLY" {
				t.Fatalf("%s: %v", method, err)
			}
		}
	}
	if passwordRead || stopped || c.EmergencyStopping() { t.Fatal("personal emergency reached password/cleanup") }
}

func TestPlayerAccountDeniesEmergencyEvenWithStaleClubMode(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.clubMode.Store(true)
	c.activation.configured = true
	c.activation.manifest.ActivationCodeFile = filepath.Join(t.TempDir(), "activation.json")
	r := activationRecord{RequestID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AccountOrigin: "https://example.test", Account: enrollment.AccountBinding{Kind:"player", Subscription:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
	b, err := json.Marshal(r)
	if err != nil { t.Fatal(err) }
	if err = os.WriteFile(c.activation.manifest.ActivationCodeFile, b, 0600); err != nil { t.Fatal(err) }
	if _, err = readActivation(c.activation.manifest); err != nil { t.Fatal("invalid fixture",err) }
	if c.emergencyClubAllowed() { t.Fatal("player inherited club emergency") }
	if err = os.WriteFile(c.activation.manifest.ActivationCodeFile, []byte("broken"), 0600); err != nil { t.Fatal(err) }
	if c.emergencyClubAllowed() { t.Fatal("unreadable role granted emergency") }
}
