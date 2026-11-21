package enrollment

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestHardwarePlaceholderBoardUsesUUIDMACWithoutChangingV2(t *testing.T) {
	h := Hardware{"10203040-5060-7080-90a0-b0c0d0e0f001", "SERIAL123", "10-11-22-33-44-55"}
	salt := make([]byte, 32)
	encoded, _ := json.Marshal([]string{"veliq-machine-v2", strings.ReplaceAll(h.UUID, "-", ""), h.BoardSerial, "10:11:22:33:44:55"})
	old := hmac.New(sha256.New, salt)
	old.Write(encoded)
	hash, d, e := HardwareHashDiagnostics(h, salt)
	if e != nil || d.Scheme != "V2_UUID_BOARD_MAC" || hash != hex.EncodeToString(old.Sum(nil)) {
		t.Fatal("existing v2 slot would change")
	}
	var fallback string
	for _, board := range []string{"Default string", "To be filled by O.E.M.", "000000", "FFFFFFFF", "", "Unknown"} {
		h.BoardSerial = board
		a, d, e := HardwareHashDiagnostics(h, salt)
		if e != nil || d.Scheme != "V3_UUID_MAC" || d.BoardSerial == "ACCEPTED" || d.UUID != "ACCEPTED" || d.MAC != "ACCEPTED" {
			t.Fatal("placeholder rejected stable remaining components", d, e)
		}
		if fallback != "" && a != fallback {
			t.Fatal("placeholder text contributed to identity")
		}
		fallback = a
		other := h
		other.UUID = "20304050-6070-8090-a0b0-c0d0e0f00102"
		other.MAC = "10-11-22-33-44-56"
		b, _, e := HardwareHashDiagnostics(other, salt)
		if e != nil || b == a {
			t.Fatal("two club PCs share identity")
		}
		uuidOnly := h
		uuidOnly.UUID = other.UUID
		macOnly := h
		macOnly.MAC = other.MAC
		for _, different := range []Hardware{uuidOnly, macOnly} {
			v, _, err := HardwareHashDiagnostics(different, salt)
			if err != nil || v == a {
				t.Fatal("UUID or MAC did not contribute to identity")
			}
		}

		raw, _ := json.Marshal(d)
		if strings.Contains(string(raw), h.UUID) || strings.Contains(string(raw), h.MAC) || strings.Contains(string(raw), board) && board != "" {
			t.Fatal("hardware value exposed")
		}
	}
}
func TestHardwareMinimumComponentsAndSafeReasons(t *testing.T) {
	salt := make([]byte, 32)
	cases := []struct {
		h      Hardware
		reason string
	}{
		{Hardware{"00000000-0000-0000-0000-000000000000", "Default string", "10:11:22:33:44:55"}, "HARDWARE_UUID_AND_BOARD_UNAVAILABLE"},
		{Hardware{"ffffffff-ffff-ffff-ffff-ffffffffffff", "None", "10:11:22:33:44:55"}, "HARDWARE_UUID_AND_BOARD_UNAVAILABLE"},
		{Hardware{"", "", "10:11:22:33:44:55"}, "HARDWARE_UUID_AND_BOARD_UNAVAILABLE"},
		{Hardware{"10203040-5060-7080-90a0-b0c0d0e0f001", "BOARD", ""}, "HARDWARE_MAC_UNAVAILABLE"},
		{Hardware{"10203040-5060-7080-90a0-b0c0d0e0f001", "BOARD", "ff:ff:ff:ff:ff:ff"}, "HARDWARE_MAC_UNAVAILABLE"},
	}
	for _, c := range cases {
		_, d, e := HardwareHashDiagnostics(c.h, salt)
		if e == nil || e.Error() != "HARDWARE_ID_UNAVAILABLE" || d.Reason != c.reason {
			t.Fatal("unsafe or incomplete rejection", d, e)
		}
	}
	a, d, e := HardwareHashDiagnostics(Hardware{"", "REAL-BOARD", "10:11:22:33:44:55"}, salt)
	if e != nil || a == "" || d.Scheme != "V3_BOARD_MAC" {
		t.Fatal("two stable components rejected")
	}
}
