// release-sign runs on the control-plane host and signs a VELIQ release manifest
// with the existing config signing key, so installed clients can verify updates
// with the trust keys they already hold. The payload is read from stdin; the
// signed envelope is written to stdout. The key never leaves the host.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/buzzmean/neexitlag/core/release"
	"github.com/buzzmean/neexitlag/core/security"
)

func run() error {
	keyFile := flag.String("key", "/etc/neexitlag/control/signing.key", "Ed25519 PKCS8 PEM")
	keyID := flag.String("key-id", "vps-1", "key id clients know from trust.json")
	flag.Parse()
	raw, e := os.ReadFile(*keyFile)
	if e != nil {
		return e
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("signing key PEM required")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return e
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return errors.New("Ed25519 signing key required")
	}
	input, e := io.ReadAll(io.LimitReader(os.Stdin, security.MaxDocument))
	if e != nil {
		return e
	}
	var m release.Manifest
	if e = security.Parse(input, &m); e != nil {
		return e
	}
	if e = m.Validate(); e != nil {
		return e
	}
	out, e := security.Sign(release.Domain, *keyID, key, m)
	if e != nil {
		return e
	}
	_, e = os.Stdout.Write(out)
	return e
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
