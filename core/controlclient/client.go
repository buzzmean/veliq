package controlclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/security"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrSubscriptionExpired: the control plane refuses relay tickets because the
// paid period (plus grace) ended. The device identity and seat stay valid.
var ErrSubscriptionExpired = errors.New("SUBSCRIPTION_EXPIRED")

// ErrNotSupported: the control plane predates the endpoint.
var ErrNotSupported = errors.New("control plane endpoint not supported")

type Client struct {
	BaseURL              string
	HTTP                 *http.Client
	Cache                *security.ConfigCache
	DeviceID             string
	DeviceKey            ed25519.PrivateKey
	AllowHTTPDevelopment bool
}

func (c *Client) request(ctx context.Context, method, path string, value any, token string) ([]byte, error) {
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("invalid control plane URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !c.AllowHTTPDevelopment && (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, errors.New("remote control plane requires HTTPS")
		}
	}
	var raw []byte
	if value != nil {
		raw, e = json.Marshal(value)
		if e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control plane redirects are disabled") }}
	}
	response, e := client.Do(req)
	if e != nil {
		return nil, errors.New("control plane request failed")
	}
	defer response.Body.Close()
	limit := security.MaxDocument
	if method == "GET" && path == "/api/v1/config" {
		limit = security.MaxConfigDocument
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if e != nil || len(b) > limit {
		return nil, errors.New("invalid control plane response size")
	}
	if response.StatusCode == http.StatusPaymentRequired {
		return nil, ErrSubscriptionExpired
	}
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusMethodNotAllowed {
		return nil, ErrNotSupported
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("control plane rejected request")
	}
	return b, nil
}
func (c *Client) Config(ctx context.Context) (security.Config, error) {
	if c.Cache == nil {
		return security.Config{}, errors.New("signed configuration cache required")
	}
	raw, e := c.request(ctx, "GET", "/api/v1/config", nil, "")
	if e == nil {
		e = c.Cache.Apply(raw, time.Now())
	}
	if e != nil {
		return c.Cache.Current(time.Now())
	}
	return c.Cache.Current(time.Now())
}
func (c *Client) Ticket(ctx context.Context, relay string) ([]byte, error) {
	if len(c.DeviceKey) != ed25519.PrivateKeySize {
		return nil, errors.New("device identity required")
	}
	proof, e := security.NewProof(c.DeviceID, relay, c.DeviceKey, time.Now())
	if e != nil {
		return nil, e
	}
	return c.request(ctx, "POST", "/api/v1/auth", proof, "")
}

// RenewCertificate asks the control plane for a fresh certificate for the same
// device key. The returned PEM must be verified by the caller before use.
func (c *Client) RenewCertificate(ctx context.Context) (string, error) {
	if len(c.DeviceKey) != ed25519.PrivateKeySize {
		return "", errors.New("device identity required")
	}
	proof, e := security.NewProof(c.DeviceID, security.RenewalAudience, c.DeviceKey, time.Now())
	if e != nil {
		return "", e
	}
	raw, e := c.request(ctx, "POST", "/api/v1/devices/renew", proof, "")
	if e != nil {
		return "", e
	}
	var out struct {
		Certificate string `json:"certificate"`
	}
	if e = security.Parse(raw, &out); e != nil || out.Certificate == "" {
		return "", errors.New("invalid renewal response")
	}
	return out.Certificate, nil
}
func (c *Client) Register(ctx context.Context, name, publicKey, adminToken string) (string, error) {
	raw, e := c.request(ctx, "POST", "/api/v1/devices", map[string]string{"id": c.DeviceID, "name": name, "public_key": publicKey}, adminToken)
	if e != nil {
		return "", e
	}
	var out struct {
		ID          string `json:"id"`
		Certificate string `json:"certificate"`
	}
	if e = security.Parse(raw, &out); e != nil {
		return "", e
	}
	return out.Certificate, nil
}

func (c *Client) Heartbeat(ctx context.Context, id, token string, load float64) error {
	_, e := c.request(ctx, "POST", "/api/v1/relays/heartbeat", map[string]any{"id": id, "healthy": true, "load": load}, token)
	return e
}

// SubscriptionStatus is this device's own paid period as the control plane sees it.
type SubscriptionStatus struct {
	Managed    bool       `json:"managed"`
	Enforced   bool       `json:"enforced"`
	Active     bool       `json:"active"`
	PaidUntil  *time.Time `json:"paid_until,omitempty"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
}

func (c *Client) SubscriptionStatus(ctx context.Context) (SubscriptionStatus, error) {
	var out SubscriptionStatus
	if len(c.DeviceKey) != ed25519.PrivateKeySize {
		return out, errors.New("device identity required")
	}
	proof, e := security.NewProof(c.DeviceID, security.SubscriptionAudience, c.DeviceKey, time.Now())
	if e != nil {
		return out, e
	}
	raw, e := c.request(ctx, "POST", "/api/v1/subscription/status", proof, "")
	if e != nil {
		return out, e
	}
	if e = security.Parse(raw, &out); e != nil {
		return out, errors.New("invalid subscription response")
	}
	return out, nil
}
