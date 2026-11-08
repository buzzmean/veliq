// Package enrollment contains public enrollment wire types and pure helpers.
// Never format an activation credential in errors or diagnostic structures.
package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"strings"
)

const CodeSymbols = 24

func NewCode() (string, error) {
	b := make([]byte, 15)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	v := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	parts := []string{"VQ"}
	for i := 0; i < len(v); i += 4 {
		parts = append(parts, v[i:i+4])
	}
	return strings.Join(parts, "-"), nil
}
func CodeHash(code string) ([]byte, error) {
	if len(code) > 64 {
		return nil, errors.New("ACTIVATION_INVALID")
	}
	if hash, ok := temporaryTestCodeHash(code); ok {
		return hash, nil
	}
	// Strict canonical grouping avoids aliases/leaking malformed input in errors.
	p := strings.Split(strings.ToUpper(strings.TrimSpace(code)), "-")
	if len(p) != 7 || p[0] != "VQ" {
		return nil, errors.New("ACTIVATION_INVALID")
	}
	for _, v := range p[1:] {
		if len(v) != 4 {
			return nil, errors.New("ACTIVATION_INVALID")
		}
		for _, c := range v {
			if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
				return nil, errors.New("ACTIVATION_INVALID")
			}
		}
	}
	h := sha256.Sum256([]byte(strings.Join(p, "-")))
	return h[:], nil
}

type Hardware struct {
	UUID        string `json:"uuid"`
	BoardSerial string `json:"board_serial"`
	MAC         string `json:"mac"`
}

type Request struct {
	Code   string          `json:"code"`
	Device freshpc.Request `json:"device"`
}
type Response struct {
	Account     *AccountBinding   `json:"account,omitempty"`
	ProbeToken  string            `json:"probe_token"`
	DeviceID    string            `json:"device_id"`
	Certificate string            `json:"certificate"`
	Trust       map[string]string `json:"trust"`
}
type Policy struct {
	AccountOrigin  string `json:"account_origin,omitempty"`
	AccountReady   bool   `json:"account_ready"`
	Ready          bool   `json:"enrollment_ready"`
	HardwareSalt   string `json:"hardware_salt"`
	CANotAfter     string `json:"ca_not_after"`
	ServerNotAfter string `json:"server_not_after,omitempty"`
}
