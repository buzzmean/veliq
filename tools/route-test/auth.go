package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/security"
)

type authenticated struct {
	control *controlclient.Client
	tls     *tls.Config
	keys    map[string]ed25519.PublicKey
	relayID string
	load    float64
}

func authenticate(ctx context.Context, o options) (authenticated, error) {
	var out authenticated
	raw, err := os.ReadFile(o.trust)
	if err != nil {
		return out, errors.New("cannot read out-of-band signing trust")
	}
	var encoded map[string]string
	if err = json.Unmarshal(raw, &encoded); err != nil {
		return out, errors.New("invalid signing trust")
	}
	out.keys = map[string]ed25519.PublicKey{}
	for id, v := range encoded {
		key, err := security.DecodePublicKey(v)
		if err != nil {
			return out, err
		}
		out.keys[id] = key
	}
	if len(out.keys) == 0 {
		return out, errors.New("empty signing trust")
	}
	identityPath := filepath.Join(o.state, "identity.json")
	if o.enrollToken == "" {
		if _, err := os.Stat(identityPath); err != nil {
			return out, errors.New("device identity absent; explicitly enroll or use existing protected device state")
		}
	}
	identity, key, err := security.LoadOrCreateIdentity(identityPath)
	if err != nil {
		return out, errors.New("invalid private device identity")
	}
	cp := &controlclient.Client{BaseURL: o.controlPlane, Cache: security.NewConfigCache(out.keys, ""), DeviceID: identity.ID, DeviceKey: key}
	if o.cpCA != "" {
		cp.HTTP, err = controlclient.HTTPSClient(o.cpCA)
		if err != nil {
			return out, err
		}
	}
	cfg, err := cp.Config(ctx)
	if err != nil {
		return out, errors.New("control plane unavailable, TLS/signing trust invalid or configuration expired")
	}
	// Key rotation is accepted only through this already verified signed config.
	for id, value := range cfg.PublicKeys {
		key, err := security.DecodePublicKey(value)
		if err != nil {
			return out, err
		}
		out.keys[id] = key
	}
	for _, node := range cfg.Relays {
		if node.ID == o.relayID && node.Address == o.relay {
			out.relayID = node.ID
			out.load = node.Load
		}
	}
	if out.relayID == "" {
		return out, errors.New("requested relay ID/address not present in verified signed registry")
	}
	certPath := filepath.Join(o.state, "device.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) && o.enrollToken != "" {
		token, err := os.ReadFile(o.enrollToken)
		if err != nil {
			return out, errors.New("cannot read private enrollment token file")
		}
		cert, err := cp.Register(ctx, "Controlled real relay test", base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), strings.TrimSpace(string(token)))
		if err != nil {
			return out, errors.New("test enrollment rejected")
		}
		if err = os.WriteFile(certPath, []byte(cert), 0600); err != nil {
			return out, err
		}
	}
	ca, err := os.ReadFile(o.ca)
	if err != nil {
		return out, errors.New("cannot read relay CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return out, errors.New("invalid relay CA")
	}
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return out, errors.New("device certificate absent; explicit enrollment required")
	}
	block, _ := pem.Decode(certRaw)
	if block == nil {
		return out, errors.New("invalid device certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return out, errors.New("invalid device certificate")
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return out, errors.New("device certificate/private identity mismatch")
	}
	out.tls = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}}}
	out.control = cp
	return out, nil
}
