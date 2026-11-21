package enrollment

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
)

// Component states only: never raw identifiers, hashes, serials or MAC addresses.
type HardwareDiagnostics struct {
	UUID        string `json:"uuid"`
	BoardSerial string `json:"board_serial"`
	MAC         string `json:"mac"`
	Scheme      string `json:"scheme"`
	Reason      string `json:"reason,omitempty"`
}

func serialState(s string) string {
	if s == "" {
		return "MISSING"
	}
	for _, bad := range []string{"DEFAULT STRING", "TO BE FILLED BY O.E.M.", "TO BE FILLED BY OEM", "NONE", "UNKNOWN", "N/A", "NOT APPLICABLE", "SYSTEM SERIAL NUMBER"} {
		if s == bad {
			return "PLACEHOLDER"
		}
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), " ", "")
	if compact != "" && (strings.Trim(compact, "0") == "" || strings.Trim(compact, "F") == "") {
		return "PLACEHOLDER"
	}
	if len(s) < 2 || len(s) > 256 {
		return "INVALID"
	}
	return "ACCEPTED"
}
func HardwareHash(h Hardware, salt []byte) (string, error) {
	v, _, e := HardwareHashDiagnostics(h, salt)
	return v, e
}
func HardwareHashDiagnostics(h Hardware, salt []byte) (string, HardwareDiagnostics, error) {
	uuid := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(h.UUID)), "-", "")
	board := strings.ToUpper(strings.TrimSpace(h.BoardSerial))
	d := HardwareDiagnostics{UUID: "ACCEPTED", BoardSerial: serialState(board), MAC: "ACCEPTED"}
	raw, e := hex.DecodeString(uuid)
	switch {
	case uuid == "":
		d.UUID = "MISSING"
	case uuid == strings.Repeat("0", 32) || uuid == strings.Repeat("f", 32):
		d.UUID = "PLACEHOLDER"
	case e != nil || len(raw) != 16:
		d.UUID = "INVALID"
	}
	mac, e := net.ParseMAC(strings.ReplaceAll(strings.TrimSpace(h.MAC), "-", ":"))
	if h.MAC == "" {
		d.MAC = "MISSING"
	} else if e != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		d.MAC = "INVALID"
	}
	switch {
	case len(salt) != 32:
		d.Reason = "HARDWARE_SALT_INVALID"
	case d.MAC != "ACCEPTED":
		d.Reason = "HARDWARE_MAC_UNAVAILABLE"
	case d.UUID != "ACCEPTED" && d.BoardSerial != "ACCEPTED":
		d.Reason = "HARDWARE_UUID_AND_BOARD_UNAVAILABLE"
	}
	if d.Reason != "" {
		return "", d, errors.New("HARDWARE_ID_UNAVAILABLE")
	}
	// Preserve v2 hashes for reliable, previously accepted components. Fallbacks use a separate domain:
	// a manufacturer placeholder contributes no entropy, even if its text changes.
	tag := "veliq-machine-v2"
	d.Scheme = "V2_UUID_BOARD_MAC"
	if d.UUID != "ACCEPTED" || d.BoardSerial != "ACCEPTED" {
		tag = "veliq-machine-v3"
		if d.UUID != "ACCEPTED" {
			uuid = ""
			d.Scheme = "V3_BOARD_MAC"
		} else {
			board = ""
			d.Scheme = "V3_UUID_MAC"
		}
	}
	b, _ := json.Marshal([]string{tag, uuid, board, mac.String()})
	m := hmac.New(sha256.New, salt)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil)), d, nil
}
