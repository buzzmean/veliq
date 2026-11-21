// dev-client validates PostgreSQL control plane -> signed ticket -> authenticated relay -> echo.
package main

import (
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
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

func run(cpURL, relayAddress, target, tokenFile, trustFile, caFile string, allowHTTP bool) error {
	raw, e := os.ReadFile(trustFile)
	if e != nil {
		return e
	}
	encoded := map[string]string{}
	if e = json.Unmarshal(raw, &encoded); e != nil {
		return e
	}
	keys := map[string]ed25519.PublicKey{}
	for id, value := range encoded {
		k, e := security.DecodePublicKey(value)
		if e != nil {
			return e
		}
		keys[id] = k
	}
	tokenRaw, e := os.ReadFile(tokenFile)
	if e != nil {
		return e
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	id, e := security.NewID()
	if e != nil {
		return e
	}
	cp := controlclient.Client{BaseURL: cpURL, Cache: security.NewConfigCache(keys, ""), DeviceID: id, DeviceKey: key, AllowHTTPDevelopment: allowHTTP}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cfg security.Config
	for {
		cfg, e = cp.Config(ctx)
		if e == nil {
			break
		}
		if ctx.Err() != nil {
			return e
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return e
		}
	}
	certPEM, e := cp.Register(ctx, "Backend integration test", base64.RawURLEncoding.EncodeToString(pub), strings.TrimSpace(string(tokenRaw)))
	if e != nil {
		return e
	}
	fmt.Println("Device registration and signed config PASS")
	relayID := ""
	for _, node := range cfg.Relays {
		if node.Address == relayAddress {
			relayID = node.ID
		}
	}
	if relayID == "" && len(cfg.Relays) > 0 {
		relayID = cfg.Relays[0].ID
	}
	if relayID == "" {
		return errors.New("relay registry is empty")
	}
	ticket, e := cp.Ticket(ctx, relayID)
	if e != nil {
		return e
	}
	pool := x509.NewCertPool()
	caRaw, e := os.ReadFile(caFile)
	if e != nil {
		return e
	}
	if !pool.AppendCertsFromPEM(caRaw) {
		return errors.New("invalid CA")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("invalid certificate")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{{Certificate: [][]byte{block.Bytes}, PrivateKey: key}}}
	client, e := transport.DialWithTicket(ctx, relayAddress, tlsConfig, ticket)
	if e != nil {
		return e
	}
	defer client.Close()
	fmt.Println("Device-bound relay ticket and local verification PASS")
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return e
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if e != nil || len(ips) == 0 {
		return errors.New("echo target resolution failed")
	}
	dst, e := netip.ParseAddrPort(net.JoinHostPort(ips[0].String(), port))
	if e != nil {
		return e
	}
	udp, e := client.OpenUDP(ctx, dst)
	if e != nil {
		return e
	}
	defer udp.Close()
	delivered := false
	for attempt := 0; attempt < 3; attempt++ {
		if e = udp.Send([]byte("udp-echo")); e != nil {
			return e
		}
		probe, stop := context.WithTimeout(ctx, time.Second)
		b, e := udp.Receive(probe)
		stop()
		if e == nil && string(b) == "udp-echo" {
			delivered = true
			break
		}
	}
	if !delivered {
		return errors.New("UDP echo delivery failed")
	}
	fmt.Println("UDP E2E PASS")
	tcp, e := client.OpenTCP(ctx, dst)
	if e != nil {
		return e
	}
	defer tcp.Close()
	tcp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = tcp.Write([]byte("tcp-echo")); e != nil {
		return e
	}
	b := make([]byte, 8)
	if _, e = io.ReadFull(tcp, b); e != nil || string(b) != "tcp-echo" {
		return errors.New("TCP echo delivery failed")
	}
	fmt.Println("TCP E2E PASS")
	return nil
}
func main() {
	cp := flag.String("control-plane", "http://127.0.0.1:8080", "control plane")
	relay := flag.String("relay-address", "127.0.0.1:4433", "relay")
	target := flag.String("target", "127.0.0.1:9000", "UDP/TCP echo target")
	token := flag.String("admin-token-file", ".dev/control/admin.token", "bootstrap token file")
	trust := flag.String("trust", ".dev/public/trust.json", "out-of-band signing trust")
	ca := flag.String("ca", ".dev/public/ca.pem", "relay CA")
	allowHTTP := flag.Bool("allow-http-development", false, "isolated development HTTP")
	flag.Parse()
	if e := run(*cp, *relay, *target, *token, *trust, *ca, *allowHTTP); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
