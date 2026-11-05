package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	URL  string
	HTTP *http.Client
}

func (c Client) call(ctx context.Context, path string, input, output any) error {
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return errors.New("ACTIVATION_TRUST_NOT_CONFIGURED")
	}
	var data []byte
	if input != nil {
		data, e = json.Marshal(input)
		if e != nil {
			return errors.New("ACTIVATION_INVALID_REQUEST")
		}
	}
	method := http.MethodGet
	if input != nil {
		method = http.MethodPost
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, bytes.NewReader(data))
	if e != nil {
		return errors.New("ACTIVATION_UNAVAILABLE")
	}
	req.Header.Set("Content-Type", "application/json")
	if c.HTTP == nil {
		return errors.New("ACTIVATION_TRUST_NOT_CONFIGURED")
	}
	httpClient := *c.HTTP
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, e := httpClient.Do(req)
	if e != nil {
		return errors.New("ACTIVATION_UNAVAILABLE")
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return errors.New("ACTIVATION_UNAVAILABLE")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var v struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &v)
		switch v.Error {
		case "ACTIVATION_INVALID", "ACTIVATION_REVOKED", "ACTIVATION_EXPIRED", "ACTIVATION_LIMIT", "MACHINE_DISABLED", "ACTIVATION_RATE_LIMIT", "ACTIVATION_IDENTITY_CONFLICT", "ACCOUNT_NOT_CONFIGURED", "MAIL_NOT_CONFIGURED", "ACCOUNT_LINK_INVALID", "ACCOUNT_LINK_EXPIRED", "ACCOUNT_LINK_UNAVAILABLE", "ACCOUNT_LINK_INVALID_RESPONSE", "ACCOUNT_SUBSCRIPTION_REQUIRED", "ACCOUNT_DEVICE_ALREADY_OWNED", "ACCOUNT_IMAGE_REVOKED", "ACCOUNT_IMAGE_LIMIT", "SUBSCRIPTION_EXPIRED":
			return errors.New(v.Error)
		}
		return errors.New("ACTIVATION_UNAVAILABLE")
	}
	if json.Unmarshal(raw, output) != nil {
		return errors.New("ACTIVATION_INVALID_RESPONSE")
	}
	return nil
}
func (c Client) Policy(ctx context.Context) (Policy, error) {
	var p Policy
	e := c.call(ctx, "/api/v1/enroll/policy", nil, &p)
	return p, e
}
func NewRequest(id, machine string, key ed25519.PrivateKey) (freshpc.Request, error) {
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id}}, key)
	if e != nil {
		return freshpc.Request{}, errors.New("ACTIVATION_KEY_FAILED")
	}
	q := freshpc.Request{DeviceID: id, MachineHash: machine, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
	_, e = freshpc.ValidateRequest(q)
	return q, e
}
func (c Client) Enroll(ctx context.Context, code string, q freshpc.Request, roots *x509.CertPool) (Response, error) {
	var out Response
	if _, e := CodeHash(code); e != nil {
		return out, e
	}
	if e := c.call(ctx, "/api/v1/enroll", Request{Code: code, Device: q}, &out); e != nil {
		return Response{}, e
	}
	if e := ValidateEnrollmentResponse(out, q, roots); e != nil {
		return Response{}, e
	}
	return out, nil
}

func ValidateEnrollmentResponse(out Response, q freshpc.Request, roots *x509.CertPool) error {
	pub, e := freshpc.ValidateRequest(q)
	if e != nil {
		return errors.New("ACTIVATION_INVALID_REQUEST")
	}
	leaf, e := freshpc.ParseCertificate(out.Certificate)
	if e != nil || out.DeviceID != q.DeviceID || leaf.IsCA || roots == nil {
		return errors.New("ACTIVATION_INVALID_RESPONSE")
	}
	k, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !k.Equal(pub) {
		return errors.New("ACTIVATION_INVALID_RESPONSE")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return errors.New("ACTIVATION_INVALID_RESPONSE")
	}
	if len(out.Trust) == 0 || len(out.Trust) > 16 {
		return errors.New("ACTIVATION_INVALID_RESPONSE")
	}
	return nil
}
