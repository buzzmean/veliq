package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/buzzmean/veliq/core/security"
)

func TestClubSharedImageThreeMachinesFreezeReusesSeatsAndRevokesOldKeys(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]string{"test": base64.RawURLEncoding.EncodeToString(pub)}
	code, raw, err := s.CreateCode(ctx, ActivationCode{Kind: "club", Name: "diskless fixture", Limit: 40, Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := enrollment.CodeHash(raw)
	salt := make([]byte, 32)
	rand.Read(salt)
	latest := map[string]string{}
	for boot := 0; boot < 3; boot++ {
		for station := 1; station <= 3; station++ {
			// Same Windows image/user SID/placeholder serial never enters the hash.
			hardware := enrollment.Hardware{UUID: fmt.Sprintf("00112233-4455-6677-8899-%012d", station), BoardSerial: "Default string", MAC: fmt.Sprintf("10:11:22:33:44:%02x", station)}
			machine, err := enrollment.HardwareHash(hardware, salt)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := security.NewID()
			pk, _, _ := ed25519.GenerateKey(rand.Reader)
			device := Device{ID: id, Name: "cloned image", PublicKey: base64.RawURLEncoding.EncodeToString(pk)}
			if err = s.EnrollCode(ctx, hash, machine, device, "test", key, trust); err != nil {
				t.Fatal(err)
			}
			if old := latest[machine]; old != "" {
				previous, err := s.Device(ctx, old)
				if err != nil || !previous.Revoked {
					t.Fatal("previous boot identity remains active")
				}
			}
			latest[machine] = id
		}
	}
	slots, err := s.CodeMachines(ctx, code.ID)
	if err != nil || len(slots) != 3 || len(latest) != 3 {
		t.Fatal("clones/freeze consumed extra seats", len(slots), err)
	}
	for _, slot := range slots {
		if slot.Device != latest[slot.Hash] || slot.Disabled {
			t.Fatal("slot not bound to latest unique machine key")
		}
	}
	var live, revoked int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FILTER (WHERE NOT revoked),count(*) FILTER (WHERE revoked) FROM devices").Scan(&live, &revoked); err != nil || live != 3 || revoked != 6 {
		t.Fatal("bad active/old identity lifecycle", live, revoked, err)
	}
}
