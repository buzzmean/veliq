// Administrative code management. No credentials via argv; creation output is
// intentionally one-time owner output, never a logfile/telemetry event.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func run() error {
	f := flag.NewFlagSet("veliq-codes", flag.ContinueOnError)
	endpoint := f.String("url", "https://127.0.0.1:8443", "control-plane HTTPS")
	ca := f.String("ca", "", "public CA file")
	token := f.String("admin-token-file", "", "root-only admin token file")
	value := f.String("value", "", "temporary test value (only test is allowed)")
	kind := f.String("kind", "personal", "club/personal")
	limit := f.Int("limit", 2, "seat limit")
	name := f.String("name", "VELIQ", "administrative label")
	days := f.Int("days", 90, "expiry days")
	after := f.String("after", "", "admin inventory cursor from previous page")
	id := f.String("id", "", "public code ID")
	machine := f.String("machine", "", "hardware hash for disable")
	if len(os.Args) < 2 {
		return fmt.Errorf("command required: create/list/machines/revoke/disable/create-test/revoke-tests")
	}
	command := os.Args[1]
	if e := f.Parse(os.Args[2:]); e != nil {
		return fmt.Errorf("invalid command options")
	}
	if !strings.HasPrefix(*endpoint, "https://") {
		return fmt.Errorf("HTTPS required")
	}
	client, e := controlclient.HTTPSClient(*ca)
	if e != nil {
		return fmt.Errorf("trusted CA required")
	}
	client.Timeout = 10 * time.Second
	secret, e := os.ReadFile(*token)
	if e != nil {
		return fmt.Errorf("admin token file unavailable")
	}
	method := http.MethodGet
	path := "/api/v1/codes"
	var payload []byte
	switch command {
	case "create-test", "revoke-tests":
		method, path, payload, e = temporaryTestOperation(command, *value, *name)
		if e != nil {
			return e
		}
	case "create":
		method = http.MethodPost
		payload, _ = json.Marshal(map[string]any{"kind": *kind, "limit": *limit, "name": *name, "expires_at": time.Now().UTC().Add(time.Duration(*days) * 24 * time.Hour)})
	case "list":
	case "machines":
		path += "/" + *id + "/machines"
	case "revoke":
		method = http.MethodPost
		path += "/" + *id + "/revoke"
	case "disable":
		method = http.MethodPost
		path += "/" + *id + "/machines/" + *machine + "/disable"
	default:
		return fmt.Errorf("unknown command")
	}
	if *after != "" {
		path += "?after=" + url.QueryEscape(*after)
	}
	req, e := http.NewRequest(method, strings.TrimRight(*endpoint, "/")+path, bytes.NewReader(payload))
	if e != nil {
		return fmt.Errorf("invalid endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(secret)))
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("control-plane unavailable")
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return fmt.Errorf("bounded response exceeded")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("code operation rejected (%d)", res.StatusCode)
	}
	_, e = os.Stdout.Write(append(raw, '\n'))
	return e
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
