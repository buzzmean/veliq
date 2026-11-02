package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

// Explicitly separate the owner UI from confidential polling/club credentials.
// Neither account secrets nor device key material are returned over this IPC.
type accountConnectionStatus struct {
	State            string    `json:"state"`
	Error            string    `json:"error,omitempty"`
	Kind             string    `json:"kind,omitempty"`
	Name             string    `json:"name,omitempty"`
	Email            string    `json:"email,omitempty"`
	CabinetURL       string    `json:"cabinet_url,omitempty"`
	VerificationURL  string    `json:"verification_url,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	ImagePreparation bool      `json:"image_preparation"`
	request          string
}
type accountImagePreparation struct {
	Version  int      `json:"version"`
	Owner    string   `json:"owner_sid"`
	Browsers []string `json:"browser_paths"`
}

func validateAccountActivationRecord(r activationRecord) error {
	fail := errors.New("ACTIVATION_STORAGE_FAILED")
	if r.Code != "" {
		return fail
	}
	if r.AccountLink != nil {
		l := r.AccountLink
		if !enrollment.AccountLinkID(l.ID) || l.ID != r.RequestID || r.AccountStarted <= 0 || (l.Mode != "device" && l.Mode != "image") {
			return fail
		}
		if _, e := enrollment.AccountSecretHash(l.Secret); e != nil {
			return fail
		}
		if l.Mode == "image" {
			if _, e := enrollment.AccountSecretHash(l.BootstrapSecret); e != nil {
				return fail
			}
		}
		return nil
	}
	if r.Account.Kind != "club" && r.Account.Kind != "player" || !enrollment.AccountLinkID(r.Account.Subscription) {
		return fail
	}
	u, e := url.Parse(r.AccountOrigin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fail
	}
	if r.BootstrapID != "" {
		if r.Account.Kind != "club" || !enrollment.AccountLinkID(r.BootstrapID) {
			return fail
		}
		if _, e = enrollment.AccountSecretHash(r.BootstrapSecret); e != nil {
			return fail
		}
	}
	if r.ImageTemplate && r.BootstrapID == "" {
		return fail
	}
	return nil
}
func accountImagePreparationPath(m Manifest) string {
	return filepath.Join(filepath.Dir(m.DeviceIdentityFile), "club-account-preparation.json")
}
func readAccountImagePreparation(m Manifest) (accountImagePreparation, bool) {
	var p accountImagePreparation
	b, e := os.ReadFile(accountImagePreparationPath(m))
	if e != nil || len(b) > 4096 || security.Parse(b, &p) != nil || p.Version != 1 || p.Owner == "" || p.Owner != m.OwnerSID || len(p.Browsers) > 2 {
		return p, false
	}
	return p, true
}
func (c *Controller) accountConnectionStatus() accountConnectionStatus {
	c.activation.mu.Lock()
	m := c.activation.manifest
	configured := c.activation.configured
	activationError := c.activation.status.Error
	c.activation.mu.Unlock()
	out := accountConnectionStatus{State: "NOT_LINKED"}
	if !configured {
		out.State = "UNAVAILABLE"
		return out
	}
	_, out.ImagePreparation = readAccountImagePreparation(m)
	r, e := readActivation(m)
	if e != nil {
		return out
	}
	if r.AccountLink != nil {
		out.State = "STARTING"
		if p := c.activation.account.Load(); p != nil && p.request == r.AccountLink.ID {
			out = *p
		}
		out.ImagePreparation = r.AccountLink.Mode == "image"
		if activationError != "" {
			out.State = "ERROR"
			out.Error = activationError
		}
		if r.AccountStarted <= 0 || time.Since(time.Unix(r.AccountStarted, 0)) > 10*time.Minute {
			out.State = "EXPIRED"
			out.Error = "ACCOUNT_LINK_EXPIRED"
			out.VerificationURL = ""
		}
		return out
	}
	if r.Account.Kind != "" {
		out.Kind = r.Account.Kind
		out.Name = r.Account.Name
		out.Email = r.Account.Email
		out.CabinetURL = r.AccountOrigin + "/account.html"
		out.State = "LINKED"
		if r.ImageTemplate {
			out.State = "IMAGE_READY"
			out.ImagePreparation = true
			if !m.ClubImage || !c.clubMode.Load() || activationError != "" {
				out.State = "ERROR"
				out.Error = "ACCOUNT_IMAGE_STORAGE_FAILED"
			}
			if clubBootReady(m) {
				out.State = "STARTING"
				out.ImagePreparation = false
			}
		} else if !validActivationIdentity(m) {
			out.State = "SIGN_IN_REQUIRED"
		}
	}
	if c.clubMode.Load() {
		out.Email = ""
		out.VerificationURL = ""
	}
	return out
}
func (c *Controller) handleAccountStart(ctx context.Context) (any, error) {
	if ctx.Err() != nil || c.ctx.Err() != nil {
		return nil, errors.New("ACCOUNT_LINK_UNAVAILABLE")
	}
	c.activation.mu.Lock()
	defer c.activation.mu.Unlock()
	if !c.activation.configured {
		return nil, errors.New("ACTIVATION_UNAVAILABLE")
	}
	m := c.activation.manifest
	if r, e := readActivation(m); e == nil && r.AccountLink != nil && r.AccountStarted > 0 && time.Since(time.Unix(r.AccountStarted, 0)) < 10*time.Minute {
		select {
		case c.activation.wake <- struct{}{}:
		default:
		}
		if p := c.activation.account.Load(); p != nil {
			return *p, nil
		}
		return accountConnectionStatus{State: "STARTING"}, nil
	}
	if _, e := os.Lstat(accountImagePreparationPath(m)); e == nil {
		if _, ok := readAccountImagePreparation(m); !ok {
			return nil, errors.New("ACCOUNT_IMAGE_NOT_CLEAN")
		}
	} else if !os.IsNotExist(e) {
		return nil, errors.New("ACCOUNT_IMAGE_STORAGE_FAILED")
	}
	mode := "device"
	if _, ok := readAccountImagePreparation(m); ok {
		if validActivationIdentity(m) {
			return nil, errors.New("ACCOUNT_IMAGE_NOT_CLEAN")
		}
		mode = "image"
	}
	l, e := enrollment.NewDeviceLink(mode)
	if e != nil {
		return nil, errors.New("ACCOUNT_LINK_UNAVAILABLE")
	}
	r := activationRecord{RequestID: l.ID, Pending: true, AccountLink: &l, AccountStarted: time.Now().Unix()}
	b, _ := json.Marshal(r)
	if e = protectedActivationWrite(pendingActivationFile(m), b); e != nil {
		return nil, e
	}
	c.activation.revision++
	c.activation.paused = false
	c.activation.status.State = "ACTIVATING"
	c.activation.status.Error = ""
	out := accountConnectionStatus{State: "STARTING", ImagePreparation: mode == "image", request: l.ID}
	c.activation.account.Store(&out)
	select {
	case c.activation.wake <- struct{}{}:
	default:
	}
	return out, nil
}
func (c *Controller) accountLinkExchange(ctx context.Context, r activationRecord, policy enrollment.Policy, client enrollment.Client, device freshpc.Request, key ed25519.PrivateKey) (enrollment.DeviceLinkStatus, error) {
	var empty enrollment.DeviceLinkStatus
	if r.AccountLink == nil || r.AccountStarted <= 0 || time.Since(time.Unix(r.AccountStarted, 0)) > 10*time.Minute {
		return empty, errors.New("ACCOUNT_LINK_EXPIRED")
	}
	if !policy.AccountReady || policy.AccountOrigin == "" {
		return empty, errors.New("ACCOUNT_NOT_CONFIGURED")
	}
	name, _ := os.Hostname()
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		name = "Компьютер VELIQ"
	}
	q, e := r.AccountLink.Request(name, device, key, time.Now())
	if e != nil {
		return empty, e
	}
	start, e := client.StartDeviceLink(ctx, q)
	if e != nil {
		return empty, e
	}
	if start.VerificationURL != policy.AccountOrigin+"/account.html#device="+r.AccountLink.ID {
		return empty, errors.New("ACCOUNT_LINK_INVALID_RESPONSE")
	}
	out := accountConnectionStatus{State: "WAITING_FOR_BROWSER", CabinetURL: policy.AccountOrigin + "/account.html", VerificationURL: start.VerificationURL, ExpiresAt: start.ExpiresAt, ImagePreparation: r.AccountLink.Mode == "image", request: r.AccountLink.ID}
	c.activation.account.Store(&out)
	result, e := client.PollDeviceLink(ctx, *r.AccountLink)
	if e != nil {
		return empty, e
	}
	if result.State == "PENDING" {
		return result, errors.New("ACCOUNT_APPROVAL_PENDING")
	}
	if result.State != "APPROVED" || (result.Account.Kind != "player" && result.Account.Kind != "club") || !enrollment.AccountLinkID(result.Account.Subscription) {
		return empty, errors.New("ACCOUNT_LINK_INVALID_RESPONSE")
	}
	return result, nil
}
func (c *Controller) accountImageAttempt(ctx context.Context, m Manifest, r activationRecord, policy enrollment.Policy, client enrollment.Client) (activationRecord, enrollment.Policy, error) {
	if _, ok := readAccountImagePreparation(m); !ok || validActivationIdentity(m) {
		return r, policy, errors.New("ACCOUNT_IMAGE_NOT_CLEAN")
	}
	result, e := c.accountLinkExchange(ctx, r, policy, client, freshpc.Request{}, nil)
	if e != nil {
		return r, policy, e
	}
	if result.Enrollment != nil || result.BootstrapID != r.AccountLink.ID || result.Account.Kind != "club" {
		return r, policy, errors.New("ACCOUNT_LINK_INVALID_RESPONSE")
	}
	r.BootstrapID = result.BootstrapID
	r.BootstrapSecret = r.AccountLink.BootstrapSecret
	r.Account = result.Account
	r.AccountOrigin = policy.AccountOrigin
	r.AccountLink = nil
	r.Pending = false
	r.ImageTemplate = true
	return r, policy, nil
}

// The installer creates the preparation marker and startup task while elevated.
// Approval itself produces only a club-scoped credential, no template key/CSR.
func (c *Controller) finishAccountImage(m Manifest, r activationRecord) error {
	p, ok := readAccountImagePreparation(m)
	if !ok || r.Account.Kind != "club" || r.BootstrapID == "" || validActivationIdentity(m) {
		return errors.New("ACCOUNT_IMAGE_NOT_CLEAN")
	}
	manifestPath := filepath.Join(filepath.Dir(m.DeviceIdentityFile), "service.json")
	b, e := os.ReadFile(manifestPath)
	if e != nil || len(b) > 128*1024 {
		return errors.New("ACCOUNT_IMAGE_STORAGE_FAILED")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return errors.New("ACCOUNT_IMAGE_STORAGE_FAILED")
	}
	var stored Manifest
	if json.Unmarshal(b, &stored) != nil || stored.OwnerSID != m.OwnerSID || stored.DeviceIdentityFile != m.DeviceIdentityFile {
		return errors.New("ACCOUNT_IMAGE_NOT_CLEAN")
	}
	fields["club_image"] = json.RawMessage("true")
	fields["club_browser_paths"], _ = json.Marshal(p.Browsers)
	b, _ = json.MarshalIndent(fields, "", "  ")
	if e = protectedActivationWrite(manifestPath, b); e != nil {
		return e
	}
	if e = wp.AllowOwnerReadFile(manifestPath, m.OwnerSID); e != nil {
		return errors.New("ACCOUNT_IMAGE_STORAGE_FAILED")
	}
	modePath := filepath.Join(filepath.Dir(m.DeviceIdentityFile), "club-mode.json")
	if e = protectedActivationWrite(modePath, []byte(`{"version":1,"enabled":true,"managed_by":"WINDOWS_ADMINISTRATOR"}`)); e != nil {
		return e
	}
	if e = wp.AllowOwnerReadFile(modePath, "S-1-1-0"); e != nil {
		return errors.New("ACCOUNT_IMAGE_STORAGE_FAILED")
	}
	m.ClubImage = true
	m.ClubBrowserPaths = p.Browsers
	c.activation.mu.Lock()
	c.activation.manifest = m
	c.activation.paused = true
	c.activation.status.State = "CLUB_IMAGE_READY"
	c.activation.status.Error = ""
	c.activation.mu.Unlock()
	if e = c.ConfigureClub(m); e != nil {
		return e
	}
	return nil
}

func accountEnrollmentResponse(ctx context.Context, c *Controller, m Manifest, r *activationRecord, policy enrollment.Policy, client enrollment.Client, request freshpc.Request, key ed25519.PrivateKey, roots *x509.CertPool) (enrollment.Response, error) {
	if r.AccountLink != nil {
		result, e := c.accountLinkExchange(ctx, *r, policy, client, request, key)
		if e != nil {
			return enrollment.Response{}, e
		}
		if result.Enrollment == nil || result.BootstrapID != "" {
			return enrollment.Response{}, errors.New("ACCOUNT_LINK_INVALID_RESPONSE")
		}
		if e = enrollment.ValidateEnrollmentResponse(*result.Enrollment, request, roots); e != nil {
			return enrollment.Response{}, e
		}
		r.Account = result.Account
		r.AccountOrigin = policy.AccountOrigin
		r.AccountLink = nil
		r.Code = ""
		return *result.Enrollment, nil
	}
	if r.BootstrapID != "" {
		out, e := client.EnrollClub(ctx, r.BootstrapID, r.BootstrapSecret, request, key, roots)
		if e != nil {
			return out, e
		}
		if out.Account == nil || out.Account.Kind != "club" || out.Account.Subscription != r.Account.Subscription {
			return enrollment.Response{}, errors.New("ACCOUNT_LINK_INVALID_RESPONSE")
		}
		r.Account = *out.Account
		r.ImageTemplate = false
		return out, nil
	}
	if r.Account.Kind != "" {
		return enrollment.Response{}, errors.New("ACCOUNT_SIGN_IN_REQUIRED")
	}
	return client.Enroll(ctx, r.Code, request, roots)
}
