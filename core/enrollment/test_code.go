package enrollment

import (
	"crypto/sha256"
	"strings"
)

// TEMPORARY OWNER TEST ONLY. Remove this exception before public release.
// No arbitrary short credentials are accepted, and no row is created implicitly.
func temporaryTestCodeHash(code string) ([]byte, bool) {
	if strings.TrimSpace(code) != "test" {
		return nil, false
	}
	hash := sha256.Sum256([]byte("test"))
	return hash[:], true
}
