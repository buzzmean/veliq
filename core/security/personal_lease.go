package security

import (
	"encoding/hex"
	"errors"
)

// PersonalOptimizationLeaseProofAudience binds the entire mutable lease action
// to the existing signed proof. A status/acquire proof cannot authorize release,
// and a renewal for one lease cannot be replayed against a different lease ID.
func PersonalOptimizationLeaseProofAudience(action, id string) (string, error) {
	if action == "acquire" {
		if id != "" {
			return "", errors.New("invalid optimization lease identity")
		}
	} else if action == "renew" || action == "release" {
		b, err := hex.DecodeString(id)
		if err != nil || len(b) != 16 || hex.EncodeToString(b) != id {
			return "", errors.New("invalid optimization lease identity")
		}
	} else {
		return "", errors.New("invalid optimization lease action")
	}
	return PersonalOptimizationLeaseAudience + ":" + action + ":" + id, nil
}
