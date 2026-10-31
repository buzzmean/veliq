package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/internal/releaseinfo"
	controlplane "github.com/buzzmean/neexitlag/services/control-plane"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func readKey(path string) (crypto.Signer, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, fmt.Errorf("invalid PEM key")
	}
	k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported signing key")
	}
	return s, nil
}
func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "HTTP listener; use TLS ingress outside localhost")
	sign := flag.String("signing-key", "", "Ed25519 PKCS8 PEM")
	kid := flag.String("key-id", "dev-1", "signing key ID")
	ca := flag.String("ca", "", "device CA PEM")
	caKey := flag.String("ca-key", "", "device CA PKCS8 PEM")
	adminTokenFile := flag.String("admin-token-file", "", "administrator token file")
	databasePasswordFile := flag.String("database-password-file", "", "database password file (overrides URL password)")
	seedRelayID := flag.String("seed-relay-id", "", "development relay registry seed ID")
	seedRelayAddress := flag.String("seed-relay-address", "", "development relay registry seed address")
	seedHeartbeatFile := flag.String("seed-heartbeat-token-file", "", "relay-specific heartbeat token seed file")
	tlsCert := flag.String("tls-cert", "", "TLS server certificate; required for remote listener")
	tlsKey := flag.String("tls-key", "", "TLS server private key")
	version := flag.Bool("version-json", false, "print build and upgrade capabilities without reading credentials or connecting to DB")
	relayTrafficFile := flag.String("relay-traffic-file", "", "optional persistent sampled NIC monthly accounting, not a routing quota")
	localLearningFile := flag.String("local-learning-file", "", "optional persistent advisory network learning; no hardware identifiers")
	localCatalogFile := flag.String("local-catalog-file", "", "optional writable reviewed catalog data file; no executable strategies")
	publish := flag.Bool("publish-config-on-start", false, "publish a complete signed configuration after additive migrations; requires upgraded config consumers")
	accountOrigin := flag.String("account-origin", "", "web cabinet origin, e.g. https://veliq.app; empty keeps the account API off")
	plansFile := flag.String("plans-file", "", "tariff JSON file (see deploy/vps/plans.example.json)")
	smtpAddr := flag.String("smtp-addr", "", "SMTP server host:port for login codes (465 = implicit TLS, otherwise STARTTLS)")
	smtpFrom := flag.String("smtp-from", "", "sender address for login codes")
	smtpUser := flag.String("smtp-user", "", "SMTP login (defaults to -smtp-from)")
	smtpPasswordFile := flag.String("smtp-password-file", "", "SMTP password file")
	plategaMerchantID := flag.String("platega-merchant-id", "", "Platega merchant id; enables online payments in the cabinet")
	plategaSecretFile := flag.String("platega-secret-file", "", "Platega API secret file (required with -platega-merchant-id)")
	plategaBaseURL := flag.String("platega-base-url", "", "Platega API base URL override; testing only, default https://app.platega.io")
	enforce := flag.Bool("enforce-subscription", false, "stop relay access for devices whose subscription or code period ended (review GET /api/v1/admin/subscriptions/cutoff first)")
	flag.Parse()
	if *version {
		if err := releaseinfo.Write(os.Stdout, "control-plane", nil, security.MaxConfigDocument, 0); err != nil {
			os.Exit(1)
		}
		return
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		slog.Error("both TLS certificate and key are required")
		os.Exit(1)
	}
	fail := func(e error) { slog.Error("control plane startup failed", "error", e); os.Exit(1) }
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	databaseURL := os.Getenv("DATABASE_URL")
	if *databasePasswordFile != "" {
		b, e := os.ReadFile(*databasePasswordFile)
		if e != nil {
			fail(e)
		}
		u, e := url.Parse(databaseURL)
		if e != nil || u.User == nil {
			fail(fmt.Errorf("database URL requires a username"))
		}
		u.User = url.UserPassword(u.User.Username(), strings.TrimSpace(string(b)))
		databaseURL = u.String()
	}
	adminToken := os.Getenv("NEEXITLAG_ADMIN_TOKEN")
	if *adminTokenFile != "" {
		b, e := os.ReadFile(*adminTokenFile)
		if e != nil {
			fail(e)
		}
		adminToken = strings.TrimSpace(string(b))
	}
	store, e := controlplane.Open(ctx, databaseURL)
	if e != nil {
		fail(e)
	}
	defer store.DB.Close()
	if e = store.Migrate(ctx); e != nil {
		fail(e)
	}
	signer, e := readKey(*sign)
	if e != nil {
		fail(e)
	}
	key, ok := signer.(ed25519.PrivateKey)
	if !ok {
		fail(fmt.Errorf("Ed25519 signing key required"))
	}
	b, e := os.ReadFile(*ca)
	if e != nil {
		fail(e)
	}
	p, _ := pem.Decode(b)
	if p == nil {
		fail(fmt.Errorf("invalid CA PEM"))
	}
	cert, e := x509.ParseCertificate(p.Bytes)
	if e != nil {
		fail(e)
	}
	cak, e := readKey(*caKey)
	if e != nil {
		fail(e)
	}
	var serverLeaf *x509.Certificate
	if *tlsCert != "" {
		raw, err := os.ReadFile(*tlsCert)
		if err != nil {
			fail(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			fail(fmt.Errorf("invalid server certificate"))
		}
		serverLeaf, e = x509.ParseCertificate(block.Bytes)
		if e != nil {
			fail(e)
		}
	}
	enrollProbeToken := ""
	if path := os.Getenv("VELIQ_ENROLL_PROBE_TOKEN_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			fail(fmt.Errorf("enrollment measurement credential unavailable"))
		}
		enrollProbeToken = strings.TrimSpace(string(raw))
		if len(enrollProbeToken) < 24 || len(enrollProbeToken) > 256 {
			fail(fmt.Errorf("invalid enrollment measurement credential"))
		}
	}
	var plans []controlplane.Plan
	if *plansFile != "" {
		if plans, e = controlplane.LoadPlans(*plansFile); e != nil {
			fail(fmt.Errorf("plans file: %w", e))
		}
	}
	var mailer controlplane.Mailer
	if *smtpAddr != "" {
		password := ""
		if *smtpPasswordFile != "" {
			raw, err := os.ReadFile(*smtpPasswordFile)
			if err != nil {
				fail(fmt.Errorf("SMTP password unavailable"))
			}
			password = strings.TrimSpace(string(raw))
		}
		mailer = controlplane.SMTPMailer{Addr: *smtpAddr, From: *smtpFrom, Username: *smtpUser, Password: password}
	}
	var payments controlplane.PaymentProvider
	if *plategaMerchantID != "" {
		if *plategaSecretFile == "" {
			fail(fmt.Errorf("platega secret file required"))
		}
		raw, err := os.ReadFile(*plategaSecretFile)
		if err != nil {
			fail(fmt.Errorf("platega secret unavailable"))
		}
		secret := strings.TrimSpace(string(raw))
		if len(secret) < 8 || len(secret) > 256 {
			fail(fmt.Errorf("invalid platega secret"))
		}
		payments = &controlplane.PlategaProvider{MerchantID: *plategaMerchantID, Secret: secret, BaseURL: *plategaBaseURL}
	}
	if *accountOrigin != "" && (!strings.HasPrefix(*accountOrigin, "https://") || strings.Count(*accountOrigin, "/") != 2) {
		fail(fmt.Errorf("account origin must look like https://host"))
	}
	api, e := controlplane.New(store, controlplane.Settings{LocalCatalogFile: *localCatalogFile, LocalLearningFile: *localLearningFile, RelayTrafficFile: *relayTrafficFile, EnrollmentProbeToken: enrollProbeToken, AdminToken: adminToken, KeyID: *kid, SigningKey: key, CA: cert, CAKey: cak, ServerCertificate: serverLeaf,
		AccountOrigin: *accountOrigin, Mailer: mailer, Plans: plans, Payments: payments, EnforceSubscription: *enforce})
	if e != nil {
		fail(e)
	}
	if *seedRelayID != "" {
		if *seedRelayAddress == "" {
			fail(fmt.Errorf("seed relay address required"))
		}
		if e = store.PutRelay(ctx, optimizer.RelayCandidate{ID: *seedRelayID, Address: *seedRelayAddress}); e != nil {
			fail(e)
		}
		if *seedHeartbeatFile != "" {
			b, e := os.ReadFile(*seedHeartbeatFile)
			if e != nil {
				fail(e)
			}
			hash := sha256.Sum256([]byte(strings.TrimSpace(string(b))))
			if e = store.SetHeartbeatToken(ctx, *seedRelayID, hash[:]); e != nil {
				fail(e)
			}
		}
	}
	if e = api.Initialize(ctx); e != nil {
		fail(e)
	}
	if *publish {
		pub := key.Public().(ed25519.PublicKey)
		if _, e = store.Publish(ctx, *kid, key, map[string]string{*kid: base64.RawURLEncoding.EncodeToString(pub)}); e != nil {
			fail(fmt.Errorf("complete configuration publication failed"))
		}
	}
	server := &http.Server{Addr: *addr, Handler: api.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	slog.Info("control plane listening", "address", *addr)
	if *tlsCert != "" {
		e = server.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		e = server.ListenAndServe()
	}
	if e != nil && e != http.ErrServerClosed {
		fail(e)
	}
}
