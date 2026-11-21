package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleTrustAndRefuseOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "bundle")
	ip := netip.MustParseAddr("192.0.2.9") // Certificate fixture only; public provisioning rejects this address.
	if e := createBundle(root, ip); e != nil {
		t.Fatal(e)
	}
	caRaw, _ := os.ReadFile(filepath.Join(root, "server/ca.pem"))
	certRaw, _ := os.ReadFile(filepath.Join(root, "server/server.pem"))
	block, _ := pem.Decode(certRaw)
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caRaw)
	if _, e = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: ip.String()}); e != nil {
		t.Fatal("VPS SAN trust", e)
	}
	if _, e = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "192.0.2.10"}); e == nil {
		t.Fatal("wrong VPS accepted")
	}
	if e = createBundle(root, ip); e == nil {
		t.Fatal("private bundle overwritten")
	}
	if _, e = os.Stat(filepath.Join(root, "windows/device/identity.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, "windows/ca.key")); !os.IsNotExist(e) {
		t.Fatal("CA private key copied to client credential scope")
	}
}
func TestRejectMissingAndNonPublicVPS(t *testing.T) {
	for _, s := range []string{"", "localhost", "127.0.0.1", "10.0.0.1", "203.0.113.9", "192.0.2.1", "198.51.100.2", "100.64.1.2", "224.0.0.1", "::1"} {
		if _, e := publicIPv4(s); e == nil {
			t.Fatal("not a real VPS", s)
		}
	}
}

// Export a loopback-only private fixture for the disposable systemd CI VM.
// This is a test entry point, never a production provisioning option.
func TestIsolatedUpgradeBundleExport(t *testing.T) {
	root := os.Getenv("NEEXITLAG_ISOLATED_UPGRADE_BUNDLE")
	if root == "" {
		t.Skip("disposable CI VM fixture only")
	}
	local := os.Getenv("VELIQ_LOCAL_FIXTURE_EXPORT") == "loopback-only" && strings.HasPrefix(filepath.Base(root), "veliq-local-fixture-")
	if (os.Getenv("GITHUB_ACTIONS") != "true" && !local) || !filepath.IsAbs(root) || filepath.Dir(root) != "/var/tmp" {
		t.Fatal("unsafe fixture destination/environment")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("fixture path must not exist")
	}
	if err := createBundle(root, netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
}
