package support

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const accountCookie = "veliq_session"
const apiPrefix = "/api/v1/account/support/"

type principal struct {
	token   string
	kind    string
	context string
}

// AccountVerifier must check the current account session on every request. A
// client-supplied email, header or visitor cookie is never account authority.
type AccountVerifier interface {
	Verify(context.Context, string) (string, error)
}

type HTTPAccountVerifier struct {
	URL    string
	Client *http.Client
}

// NewAccountVerifier pins the upstream URL, verifies its certificate and never
// follows redirects with account credentials. No database or administrative API
// credentials are shared with support.
func NewAccountVerifier(endpoint, caFile string) (*HTTPAccountVerifier, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/api/v1/account" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid_account_endpoint")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("account_trust_unavailable")
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid_account_ca")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &HTTPAccountVerifier{URL: endpoint, Client: &http.Client{
		Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (v *HTTPAccountVerifier) Verify(ctx context.Context, token string) (string, error) {
	if len(token) != 43 || strings.ContainsAny(token, "\r\n; ") {
		return "", ErrUnauthorized
	}
	r, err := http.NewRequestWithContext(ctx, "GET", v.URL, nil)
	if err != nil {
		return "", errors.New("account_unavailable")
	}
	r.AddCookie(&http.Cookie{Name: accountCookie, Value: token})
	r.Header.Set("Accept", "application/json")
	res, err := v.Client.Do(r)
	if err != nil {
		return "", errors.New("account_unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return "", ErrUnauthorized
	}
	if res.StatusCode != 200 {
		return "", errors.New("account_unavailable")
	}
	var body struct {
		AccountID string `json:"account_id"`
	}
	d := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	if d.Decode(&body) != nil {
		return "", errors.New("account_unavailable")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return "", errors.New("account_unavailable")
	}
	id := body.AccountID
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 || id != strings.ToLower(id) {
		return "", errors.New("account_identity_unavailable")
	}
	return id, nil
}

func (s *Server) identify(ctx context.Context, r *http.Request) (principal, error) {
	guest := ""
	if c, err := r.Cookie(cookieName); err == nil && validID(c.Value) {
		guest = c.Value
	}
	p := principal{token: guest, kind: "guest", context: hash("guest-context\x00" + guest)}
	var tokens []string
	for _, c := range r.Cookies() {
		if c.Name == accountCookie {
			tokens = append(tokens, c.Value)
		}
	}
	if len(tokens) == 0 {
		return p, nil
	}
	if len(tokens) != 1 {
		return principal{}, ErrUnauthorized
	}
	if s.Accounts == nil {
		return principal{}, errors.New("account_unavailable")
	}
	accountID, err := s.Accounts.Verify(ctx, tokens[0])
	if err != nil {
		return principal{}, err
	}
	p = principal{token: hash("verified-account\x00" + accountID), kind: "account", context: hash("account-context\x00" + accountID + "\x00" + tokens[0])}
	// Revoke this browser's guest access, without moving or deleting its tickets.
	if guest != "" {
		if _, err = s.Store.DB.Exec(ctx, `UPDATE support_visitors SET expires_at=now() WHERE id=$1 AND owner_kind='guest'`, hash(guest)); err != nil {
			return principal{}, err
		}
	}
	return p, nil
}

func (s *Store) ensureAccount(ctx context.Context, p principal) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO support_visitors(id,expires_at,owner_kind) VALUES($1,now()+interval '30 days','account')
 ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at WHERE support_visitors.owner_kind='account'`, hash(p.token))
	return err
}
