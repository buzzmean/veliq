// Read-only owner proof/bandwidth tool. Uses the installed identity without
// creating/enrolling/revoking it. No capture, driver, policy or browser changes.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/clientconfig"
	"github.com/buzzmean/veliq/internal/e2eprobe"
)

type manifest = clientconfig.Manifest

func publicKeyMatches(leaf *x509.Certificate, key ed25519.PrivateKey) bool {
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	return ok && pub.Equal(key.Public())
}
func connect(ctx context.Context, path, id, address string) (*transport.Client, manifest, error) {
	m, e := clientconfig.Load(path)
	if e != nil {
		return nil, m, errors.New("INSTALLED_MANIFEST_REQUIRED")
	}
	b, e := os.ReadFile(m.DeviceIdentityFile)
	var identity security.Identity
	if e != nil || security.Parse(b, &identity) != nil {
		return nil, m, errors.New("EXISTING_IDENTITY_REQUIRED")
	}
	seed, e := base64.RawURLEncoding.DecodeString(identity.Seed)
	if e != nil || len(seed) != 32 {
		return nil, m, errors.New("IDENTITY_FORMAT")
	}
	key := ed25519.NewKeyFromSeed(seed)
	b, e = os.ReadFile(m.DeviceCertificate)
	if e != nil {
		return nil, m, errors.New("DEVICE_CERTIFICATE_REQUIRED")
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, m, errors.New("DEVICE_CERTIFICATE_FORMAT")
	}
	leaf, e := x509.ParseCertificate(p.Bytes)
	if e != nil || !publicKeyMatches(leaf, key) {
		return nil, m, errors.New("DEVICE_KEY_MISMATCH")
	}
	b, e = os.ReadFile(m.CAFile)
	roots := x509.NewCertPool()
	if e != nil || !roots.AppendCertsFromPEM(b) {
		return nil, m, errors.New("CA_REQUIRED")
	}
	ca := m.ControlPlaneCAFile
	if ca == "" {
		ca = m.CAFile
	}
	hc, e := controlclient.HTTPSClient(ca)
	if e != nil {
		return nil, m, e
	}
	cc := &controlclient.Client{BaseURL: m.ControlPlaneURL, HTTP: hc, DeviceID: identity.ID, DeviceKey: key}
	ticket, e := cc.Ticket(ctx, id)
	if e != nil {
		return nil, m, errors.New("SIGNED_DEVICE_PROOF_TICKET_FAILED")
	}
	raw, e := os.ReadFile(m.TrustFile)
	var trust map[string]string
	if e != nil || json.Unmarshal(raw, &trust) != nil {
		return nil, m, errors.New("SIGNING_TRUST_REQUIRED")
	}
	keys := map[string]ed25519.PublicKey{}
	for id, v := range trust {
		k, e := security.DecodePublicKey(v)
		if e != nil {
			return nil, m, e
		}
		keys[id] = k
	}
	var signed security.Ticket
	if security.Verify("ticket", keys, ticket, &signed) != nil || signed.DeviceID != identity.ID || signed.DeviceKey != security.Fingerprint(key.Public().(ed25519.PublicKey)) || signed.RelayID != id || !signed.ExpiresAt.After(time.Now()) {
		return nil, m, errors.New("TICKET_BINDING_FAILED")
	}
	host, _, e := net.SplitHostPort(address)
	if e != nil {
		return nil, m, errors.New("RELAY_ADDRESS_REQUIRED")
	}
	c, e := transport.DialWithTicket(ctx, address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: host, Certificates: []tls.Certificate{{Certificate: [][]byte{p.Bytes}, PrivateKey: key}}}, ticket)
	if e != nil {
		return nil, m, errors.New("QUIC_MTLS_TICKET_HANDSHAKE_FAILED")
	}
	if !c.Renewable() {
		c.Close()
		return nil, m, errors.New("PROTOCOL_3_REQUIRED")
	}
	return c, m, nil
}

func probeEcho(ctx context.Context, c *transport.Client, m manifest) error {
	key, e := e2eprobe.Token(m.ProbeTokenFile)
	if e != nil {
		return errors.New("UDP_PROBE_TOKEN_UNAVAILABLE")
	}
	dst, e := netip.ParseAddrPort(m.ProbeTarget)
	if e != nil || dst.Port() == 53 {
		return errors.New("PROBE_TARGET_INVALID")
	}
	flow, e := e2eprobe.ProbeOpener(c.OpenDatagram, key)(ctx, dst)
	if e != nil {
		return errors.New("UDP_OPEN_FAILED")
	}
	defer flow.Close()
	p := make([]byte, 32)
	rand.Read(p)
	if flow.Send(p) != nil {
		return errors.New("UDP_SEND_FAILED")
	}
	got, e := flow.Receive(ctx)
	if e != nil || !bytes.Equal(got, p) {
		return errors.New("UDP_AUTHENTICATED_ECHO_FAILED")
	}
	return nil
}

func probe(ctx context.Context, c *transport.Client, m manifest) error {
	if err := probeEcho(ctx, c, m); err != nil {
		return err
	}
	raw, e := c.OpenTCP(ctx, netip.MustParseAddrPort("1.1.1.1:443"))
	if e != nil {
		return errors.New("TCP_OPEN_FAILED")
	}
	defer raw.Close()
	if d, ok := ctx.Deadline(); ok {
		raw.SetDeadline(d)
	}
	t := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "cloudflare-dns.com", NextProtos: []string{"http/1.1"}})
	if t.HandshakeContext(ctx) != nil {
		return errors.New("PUBLIC_ORIGIN_TLS_FAILED")
	}
	req, _ := http.NewRequest("GET", "https://cloudflare-dns.com/dns-query?name=example.com&type=A", nil)
	req.Header.Set("Accept", "application/dns-json")
	req.Close = true
	if req.Write(t) != nil {
		return errors.New("PUBLIC_HTTP_WRITE_FAILED")
	}
	r, e := http.ReadResponse(bufio.NewReader(t), req)
	if e != nil {
		return errors.New("PUBLIC_HTTP_RESPONSE_FAILED")
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	var dns struct {
		Status int
		Answer []json.RawMessage
	}
	if e != nil || len(b) > 65536 || r.StatusCode != 200 || json.Unmarshal(b, &dns) != nil || dns.Status != 0 || len(dns.Answer) == 0 {
		return errors.New("PUBLIC_TLS_HTTP_DNS_PROOF_FAILED")
	}
	return nil
}
func run() error {
	f := flag.NewFlagSet("relay-client", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "probe", "probe/status/fleet-staged")
	target := f.String("probe-target", "", "exact staged echo target, required for fleet-staged")
	id := f.String("relay-id", "VPS-01", "signed relay identity")
	address := f.String("address", "", "literal IPv4:4433")
	manifestPath := f.String("manifest", filepath.Join(os.Getenv("ProgramData"), "neexitlag", "service.json"), "installed manifest")
	seconds := f.Int("timeout", 60, "10..90 seconds")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 || *seconds < 10 || *seconds > 90 {
		return errors.New("BOUNDED_ARGUMENTS_INVALID")
	}
	if *mode == "status" {
		return cachedStatus(*manifestPath)
	}
	a, e := netip.ParseAddrPort(*address)
	if *mode == "fleet-staged" {
		explicit := false
		f.Visit(func(opt *flag.Flag) {
			if opt.Name == "manifest" {
				explicit = true
			}
		})
		if e != nil || a.Port() == 0 || !security.FleetNodeID(*id) || !explicit || *target == "" {
			return errors.New("EXPLICIT_STAGE_MANIFEST_ADDRESS_AND_PROBE_REQUIRED")
		}
		staged, e := clientconfig.Load(*manifestPath)
		if e != nil || staged.ProbeTarget != *target {
			return errors.New("STAGED_PROBE_TARGET_MISMATCH")
		}
	} else if *mode != "probe" || *target != "" || e != nil || !a.Addr().Is4() || !a.Addr().IsGlobalUnicast() || a.Addr().IsPrivate() || (a.Port() != 4433 && a.Port() != 4434) {
		return errors.New("EXPLICIT_PUBLIC_RELAY_REQUIRED")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*seconds)*time.Second)
	defer cancel()
	start := time.Now()
	c, m, e := connect(ctx, *manifestPath, *id, *address)
	if e != nil {
		return e
	}
	defer c.Close()
	setupMS := float64(time.Since(start)) / float64(time.Millisecond)
	if *mode == "fleet-staged" {
		if m.ProbeTarget != *target {
			return errors.New("STAGED_PROBE_TARGET_MISMATCH")
		}
		if e = probeEcho(ctx, c, m); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"pass": true, "relay_id": *id, "address": *address, "probe_target": *target,
			"proof": "verified_mtls_audience_authenticated_udp_echo",
		})
	}
	if *mode == "probe" {
		if e = probe(ctx, c, m); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"pass": true, "relay_id": *id, "address": *address, "setup_ms": setupMS, "proof": "fresh signed device ticket; verified QUIC mTLS /3; authenticated UDP echo; public certificate+TLS+HTTP DNS response"})
	}
	return errors.New("MODE_INVALID")
}

func cachedStatus(path string) error {
	m, e := clientconfig.Load(path)
	if e != nil {
		return errors.New("INSTALLED_MANIFEST_REQUIRED")
	}
	raw, e := os.ReadFile(m.TrustFile)
	var encoded map[string]string
	if e != nil || json.Unmarshal(raw, &encoded) != nil {
		return errors.New("SIGNING_TRUST_REQUIRED")
	}
	keys := map[string]ed25519.PublicKey{}
	for id, value := range encoded {
		k, e := security.DecodePublicKey(value)
		if e != nil {
			return errors.New("SIGNING_TRUST_INVALID")
		}
		keys[id] = k
	}
	cache := security.NewConfigCache(keys, filepath.Join(m.StateDirectory, "signed-config.json"))
	if cache.Load(time.Now()) != nil {
		return errors.New("VALID_INSTALLED_SIGNED_CONFIG_REQUIRED")
	}
	cfg, e := cache.Current(time.Now())
	if e != nil {
		return errors.New("SIGNED_CONFIG_EXPIRED")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"source": "installed service signed cache; no network request", "version": cfg.Version, "relays": cfg.Relays, "actual_established_endpoints": "NOT_INSTRUMENTED_IN_LEGACY_CLIENT; existing streams may still use the old endpoint", "new_connections": "use endpoint after service applies this config; pool snapshot is checked separately"})
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
