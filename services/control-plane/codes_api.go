package controlplane

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"net/http"
	"strings"
	"time"
)

func (a *API) enrollmentPolicy(w http.ResponseWriter, r *http.Request) {
	salt, e := a.Store.HardwareSalt(r.Context())
	if e != nil {
		a.fail(w, 503, "ACTIVATION_UNAVAILABLE")
		return
	}
	p := enrollment.Policy{Ready: len(a.Settings.EnrollmentProbeToken) >= 24, HardwareSalt: salt, CANotAfter: a.Settings.CA.NotAfter.UTC().Format(time.RFC3339)}
	p.AccountReady = a.accountLinkAvailable()
	if p.AccountReady {
		p.AccountOrigin = a.Settings.AccountOrigin
	}
	if a.Settings.ServerCertificate != nil {
		p.ServerNotAfter = a.Settings.ServerCertificate.NotAfter.UTC().Format(time.RFC3339)
	}
	respond(w, 200, p)
}
func (a *API) enroll(w http.ResponseWriter, r *http.Request) {
	if !a.enrollIP.allow(time.Now(), sourceKey(r)) {
		a.fail(w, 429, "ACTIVATION_RATE_LIMIT")
		return
	}
	var q enrollment.Request
	if body(r, &q) != nil {
		a.fail(w, 400, "ACTIVATION_INVALID")
		return
	}
	hash, e := enrollment.CodeHash(q.Code)
	if e != nil {
		a.fail(w, 401, "ACTIVATION_INVALID")
		return
	}
	if !a.enrollCode.allow(time.Now(), hex.EncodeToString(hash)) {
		a.fail(w, 429, "ACTIVATION_RATE_LIMIT")
		return
	}
	if len(a.Settings.EnrollmentProbeToken) < 24 {
		a.fail(w, 503, "ACTIVATION_UNAVAILABLE")
		return
	}
	pub, e := freshpc.ValidateRequest(q.Device)
	if e != nil {
		a.fail(w, 400, "ACTIVATION_INVALID_REQUEST")
		return
	}
	der, e := issueClientCertificate(a.Settings.CA, a.Settings.CAKey, pub, time.Now())
	if e != nil {
		a.fail(w, 503, "ACTIVATION_UNAVAILABLE")
		return
	}
	trust := map[string]string{a.Settings.KeyID: base64.RawURLEncoding.EncodeToString(a.Settings.SigningKey.Public().(ed25519.PublicKey))}
	e = a.Store.EnrollCode(r.Context(), hash, q.Device.MachineHash, Device{ID: q.Device.DeviceID, Name: "VELIQ device", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}, a.Settings.KeyID, a.Settings.SigningKey, trust)
	if e != nil {
		code := activationError(e.Error())
		status := 503
		if code != "ACTIVATION_UNAVAILABLE" {
			status = 403
		}
		a.fail(w, status, code)
		return
	}
	respond(w, 201, enrollment.Response{ProbeToken: a.Settings.EnrollmentProbeToken, DeviceID: q.Device.DeviceID, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Trust: trust})
}
func activationError(s string) string {
	switch s {
	case "ACTIVATION_INVALID", "ACTIVATION_REVOKED", "ACTIVATION_EXPIRED", "ACTIVATION_LIMIT", "MACHINE_DISABLED", "ACTIVATION_IDENTITY_CONFLICT":
		return s
	}
	return "ACTIVATION_UNAVAILABLE"
}
func (a *API) codes(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.fail(w, 401, "administrator authorization required")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/codes")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if path == "" || path == "/" {
		switch r.Method {
		case "GET":
			out, next, e := a.Store.CodesPage(r.Context(), r.URL.Query().Get("after"))
			if e != nil {
				a.fail(w, 503, "ACTIVATION_UNAVAILABLE")
				return
			}
			respond(w, 200, map[string]any{"codes": out, "next_cursor": next})
		case "POST":
			var c ActivationCode
			if body(r, &c) != nil {
				a.fail(w, 400, "ACTIVATION_CONFIGURATION_INVALID")
				return
			}
			c, code, e := a.Store.CreateCode(r.Context(), c)
			if e != nil {
				a.fail(w, 400, "ACTIVATION_CONFIGURATION_INVALID")
				return
			}
			respond(w, 201, struct {
				ActivationCode
				Code string `json:"code"`
			}{c, code})
		default:
			a.fail(w, 405, "method not allowed")
		}
		return
	}
	// TEMPORARY OWNER TEST ONLY: both operations require the admin check above.
	if len(parts) == 1 && parts[0] == "test" && r.Method == "POST" {
		var q struct {
			Value string `json:"value"`
			Name  string `json:"name"`
		}
		if body(r, &q) != nil {
			a.fail(w, 400, "ACTIVATION_CONFIGURATION_INVALID")
			return
		}
		c, err := a.Store.CreateTestCode(r.Context(), q.Value, q.Name)
		if err != nil {
			code := "ACTIVATION_CONFIGURATION_INVALID"
			status := 400
			if err.Error() == "TEST_CODE_ALREADY_EXISTS" {
				code = "TEST_CODE_ALREADY_EXISTS"
				status = 409
			}
			if err.Error() == "ACTIVATION_UNAVAILABLE" {
				code = "ACTIVATION_UNAVAILABLE"
				status = 503
			}
			a.fail(w, status, code)
			return
		}
		respond(w, 201, c)
		return
	}
	if len(parts) == 1 && parts[0] == "revoke-tests" && r.Method == "POST" {
		pub := a.Settings.SigningKey.Public().(ed25519.PublicKey)
		n, err := a.Store.RevokeTestCodes(r.Context(), a.Settings.KeyID, a.Settings.SigningKey, map[string]string{a.Settings.KeyID: base64.RawURLEncoding.EncodeToString(pub)})
		if err != nil {
			a.fail(w, 503, "ACTIVATION_UNAVAILABLE")
			return
		}
		respond(w, 200, map[string]any{"status": "revoked", "test_codes_revoked": n})
		return
	}
	if len(parts) == 2 && parts[1] == "machines" && r.Method == "GET" {
		out, next, e := a.Store.MachinesPage(r.Context(), parts[0], r.URL.Query().Get("after"))
		if e != nil {
			a.fail(w, 503, "ACTIVATION_UNAVAILABLE")
			return
		}
		respond(w, 200, map[string]any{"machines": out, "next_cursor": next})
		return
	}
	machine := ""
	valid := len(parts) == 2 && parts[1] == "revoke"
	if len(parts) == 4 && parts[1] == "machines" && parts[3] == "disable" {
		machine = parts[2]
		valid = true
	}
	if r.Method != "POST" || !valid || len(parts[0]) != 32 {
		a.fail(w, 400, "ACTIVATION_CONFIGURATION_INVALID")
		return
	}
	pub := a.Settings.SigningKey.Public().(ed25519.PublicKey)
	if e := a.Store.RevokeCode(r.Context(), parts[0], machine, a.Settings.KeyID, a.Settings.SigningKey, map[string]string{a.Settings.KeyID: base64.RawURLEncoding.EncodeToString(pub)}); e != nil {
		if e.Error() == "ACTIVATION_NOT_FOUND" {
			a.fail(w, 404, "ACTIVATION_NOT_FOUND")
		} else {
			a.fail(w, 503, "ACTIVATION_UNAVAILABLE")
		}
		return
	}
	respond(w, 200, map[string]string{"status": "revoked"})
}
