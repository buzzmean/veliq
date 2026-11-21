package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/security"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	url := flag.String("control-plane", "http://127.0.0.1:8080", "control plane endpoint")
	dir := flag.String("state", ".dev/device", "device state directory")
	name := flag.String("name", "Development device", "device name")
	tokenFile := flag.String("admin-token-file", "", "bootstrap token file (or NEEXITLAG_ADMIN_TOKEN)")
	ca := flag.String("ca", "", "explicit private TLS CA for control plane")
	flag.Parse()
	token := os.Getenv("NEEXITLAG_ADMIN_TOKEN")
	if *tokenFile != "" {
		b, e := os.ReadFile(*tokenFile)
		if e != nil {
			fmt.Fprintln(os.Stderr, "cannot read bootstrap token file")
			os.Exit(1)
		}
		token = strings.TrimSpace(string(b))
	}
	id, key, e := security.LoadOrCreateIdentity(filepath.Join(*dir, "identity.json"))
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	client := controlclient.Client{BaseURL: *url, DeviceID: id.ID, DeviceKey: key}
	if *ca != "" {
		client.HTTP, e = controlclient.HTTPSClient(*ca)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cert, e := client.Register(ctx, *name, base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), token)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e = os.WriteFile(filepath.Join(*dir, "device.pem"), []byte(cert), 0600); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("Device enrolled; certificate and private identity saved locally.")
}
