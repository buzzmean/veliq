package enrollment

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestTemporaryLiteralCredentialHashOnly(t *testing.T) {
	expected := sha256.Sum256([]byte("test"))
	for _, v := range []string{"test", " test\n"} {
		hash, err := CodeHash(v)
		if err != nil || !bytes.Equal(hash, expected[:]) {
			t.Fatal("temporary code canonical hash", err)
		}
	}
	for _, v := range []string{"TEST", "Test", "tes", "testing", "admin", "1234"} {
		if _, err := CodeHash(v); err == nil {
			t.Fatal("arbitrary short code accepted")
		}
	}
}
