package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/buzzmean/neexitlag/core/freshpc"
)

// DeviceLink is an expiring browser approval, never a human activation code.
// Secret and BootstrapSecret belong only in SYSTEM-protected storage, not IPC.
type DeviceLink struct {
	ID              string `json:"id"`
	Secret          string `json:"secret"`
	Mode            string `json:"mode"`
	BootstrapSecret string `json:"bootstrap_secret,omitempty"`
}
type DeviceLinkRequest struct {
	ID            string          `json:"id"`
	Secret        string          `json:"secret"`
	Mode          string          `json:"mode"`
	Name          string          `json:"name"`
	Device        freshpc.Request `json:"device"`
	BootstrapHash string          `json:"bootstrap_hash,omitempty"`
	IssuedAt      int64           `json:"issued_at"`
	Signature     string          `json:"signature,omitempty"`
}
type AccountBinding struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Email        string `json:"email,omitempty"`
	Subscription string `json:"subscription_id"`
}
type DeviceLinkStatus struct {
	State           string         `json:"state"`
	VerificationURL string         `json:"verification_url,omitempty"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Interval        int            `json:"interval_seconds"`
	Account         AccountBinding `json:"account"`
	Enrollment      *Response      `json:"enrollment,omitempty"`
	BootstrapID     string         `json:"bootstrap_id,omitempty"`
}
type DeviceLinkPoll struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}
type ClubEnrollmentRequest = DeviceLinkRequest

func NewDeviceLink(mode string) (DeviceLink, error) {
	if mode != "device" && mode != "image" {
		return DeviceLink{}, errors.New("ACCOUNT_LINK_INVALID")
	}
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return DeviceLink{}, err
	}
	l := DeviceLink{ID: hex.EncodeToString(b[:16]), Secret: base64.RawURLEncoding.EncodeToString(b[16:]), Mode: mode}
	if mode == "image" {
		if _, err := rand.Read(b[:32]); err != nil {
			return DeviceLink{}, err
		}
		l.BootstrapSecret = base64.RawURLEncoding.EncodeToString(b[:32])
	}
	return l, nil
}
func AccountSecretHash(secret string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != secret {
		return nil, errors.New("ACCOUNT_LINK_INVALID")
	}
	h := sha256.Sum256([]byte("neexitlag:device-link-secret:v1\x00" + secret))
	return h[:], nil
}
func AccountLinkID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == id
}
func (q DeviceLinkRequest) signed() []byte {
	q.Signature = ""
	b, _ := json.Marshal(q)
	return append([]byte("neexitlag:device-link-request:v1\x00"), b...)
}
func (l DeviceLink) Request(name string, device freshpc.Request, key ed25519.PrivateKey, now time.Time) (DeviceLinkRequest, error) {
	q := DeviceLinkRequest{ID: l.ID, Secret: l.Secret, Mode: l.Mode, Name: name, Device: device, IssuedAt: now.Unix()}
	if l.Mode == "image" {
		h, e := AccountSecretHash(l.BootstrapSecret)
		if e != nil {
			return q, e
		}
		q.BootstrapHash = hex.EncodeToString(h)
	} else {
		if len(key) != ed25519.PrivateKeySize {
			return q, errors.New("ACCOUNT_LINK_INVALID")
		}
		q.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, q.signed()))
	}
	_, e := q.Validate(now)
	return q, e
}
func (q DeviceLinkRequest) Validate(now time.Time) (ed25519.PublicKey, error) {
	fail := errors.New("ACCOUNT_LINK_INVALID")
	if !AccountLinkID(q.ID) || len(q.Name) < 1 || len(q.Name) > 128 || strings.TrimSpace(q.Name) != q.Name || strings.IndexFunc(q.Name, unicode.IsControl) >= 0 || q.IssuedAt < now.Add(-90*time.Second).Unix() || q.IssuedAt > now.Add(30*time.Second).Unix() {
		return nil, fail
	}
	if _, e := AccountSecretHash(q.Secret); e != nil {
		return nil, fail
	}
	if q.Mode == "image" {
		h, e := hex.DecodeString(q.BootstrapHash)
		if e != nil || len(h) != 32 || hex.EncodeToString(h) != q.BootstrapHash || q.Signature != "" || q.Device != (freshpc.Request{}) {
			return nil, fail
		}
		return nil, nil
	}
	if q.Mode != "device" || q.BootstrapHash != "" {
		return nil, fail
	}
	pub, e := freshpc.ValidateRequest(q.Device)
	sig, se := base64.RawURLEncoding.DecodeString(q.Signature)
	if e != nil || se != nil || !ed25519.Verify(pub, q.signed(), sig) {
		return nil, fail
	}
	return pub, nil
}
func (c Client) StartDeviceLink(ctx context.Context, q DeviceLinkRequest) (DeviceLinkStatus, error) {
	var out DeviceLinkStatus
	e := c.call(ctx, "/api/v1/enroll/device/start", q, &out)
	if e == nil {
		u, ue := url.Parse(out.VerificationURL)
		if ue != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Path != "/account.html" || u.Fragment != "device="+q.ID || out.State != "PENDING" || out.Interval < 2 || out.Interval > 10 || !out.ExpiresAt.After(time.Now()) || out.ExpiresAt.After(time.Now().Add(11*time.Minute)) {
			e = errors.New("ACCOUNT_LINK_INVALID_RESPONSE")
		}
	}
	return out, e
}
func (c Client) PollDeviceLink(ctx context.Context, l DeviceLink) (DeviceLinkStatus, error) {
	var out DeviceLinkStatus
	e := c.call(ctx, "/api/v1/enroll/device/poll", DeviceLinkPoll{ID: l.ID, Secret: l.Secret}, &out)
	return out, e
}
func (c Client) EnrollClub(ctx context.Context, id, secret string, q freshpc.Request, key ed25519.PrivateKey, roots *x509.CertPool) (Response, error) {
	var out Response
	proof, e := (DeviceLink{ID: id, Secret: secret, Mode: "device"}).Request("club-boot", q, key, time.Now())
	if e != nil {
		return out, e
	}
	e = c.call(ctx, "/api/v1/enroll/club", proof, &out)
	if e == nil {
		e = ValidateEnrollmentResponse(out, q, roots)
	}
	return out, e
}
