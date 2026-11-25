package controlclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/security"
)

type DiagnosticHTTPError struct{ Status int }

func (e DiagnosticHTTPError) Error() string { return "diagnostic HTTP status" }

// Uses the device proof and the existing verified CP transport. Unlike request,
// this path retains typed transport errors without exposing error strings.
func (c *Client) ClubHealthPersistent(ctx context.Context, b clubhealth.Batch) (clubhealth.Receipt, error) {
	var out clubhealth.Receipt
	if len(c.DeviceKey) != ed25519.PrivateKeySize {
		return out, errors.New("device identity required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(c.AllowHTTPDevelopment && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))) {
		return out, errors.New("invalid diagnostic server")
	}
	if err = b.Validate(time.Now()); err != nil {
		return out, err
	}
	proof, err := security.NewProof(c.DeviceID, b.Audience(), c.DeviceKey, time.Now())
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(clubhealth.PersistentRequest{Batch: b, Proof: proof})
	if err != nil {
		return out, err
	}
	u.Path = clubhealth.PersistentEndpoint
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 8 * time.Second}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return out, DiagnosticHTTPError{Status: res.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil {
		return out, err
	}
	if len(body) > 4096 || security.Parse(body, &out) != nil || !out.Accepts(b) {
		return out, errors.New("diagnostic durable acknowledgement missing")
	}
	return out, nil
}
