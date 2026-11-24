// Package deviceinfo описывает сведения, которые компьютер сообщает о себе.
package deviceinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/buzzmean/neexitlag/core/security"
)

type Details struct {
	ComputerName string `json:"computer_name"`
	Version      string `json:"version"`
}

type Request struct {
	Details Details        `json:"details"`
	Proof   security.Proof `json:"proof"`
}

func (d Details) Valid() bool {
	if !utf8.ValidString(d.ComputerName) || strings.TrimSpace(d.ComputerName) != d.ComputerName ||
		len(d.ComputerName) == 0 || len(d.ComputerName) > 128 || len(d.Version) > 80 {
		return false
	}
	for _, r := range d.ComputerName {
		if unicode.IsControl(r) || strings.ContainsRune(`/\:"<>|?*`, r) {
			return false
		}
	}
	for _, r := range d.Version {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune(".+-_", r)) {
			return false
		}
	}
	return true
}

// Audience связывает подпись устройства с содержимым сведений о нём.
func (d Details) Audience() string {
	raw, _ := json.Marshal(d)
	hash := sha256.Sum256(raw)
	return "veliq:device-details:v1:" + hex.EncodeToString(hash[:])
}
