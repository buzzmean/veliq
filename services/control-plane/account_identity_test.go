package controlplane

import (
	"encoding/hex"
	"testing"
)

func TestAccountViewExposesOnlyAuthenticatedStableIdentity(t *testing.T) {
	api, _, mailer := accountAPI(t, false)
	a, b := &call{api: api}, &call{api: api, ip: "198.51.100.9"}
	if status, out := a.do(t, "GET", "/api/v1/account", nil); status != 401 || out["account_id"] != nil {
		t.Fatal("anonymous identity exposed")
	}
	login(t, a, mailer, "support-owner-a@example.test")
	status, first := a.do(t, "GET", "/api/v1/account", nil)
	id, ok := first["account_id"].(string)
	decoded, err := hex.DecodeString(id)
	if status != 200 || !ok || err != nil || len(decoded) != 16 {
		t.Fatal("missing account identity")
	}
	if status, out := a.do(t, "POST", "/api/v1/account/profile", map[string]string{"kind": "player", "name": "Changed name"}); status != 200 {
		t.Fatal(status, out)
	}
	if status, out := a.do(t, "GET", "/api/v1/account", nil); status != 200 || out["account_id"] != id {
		t.Fatal("identity changed with profile")
	}
	login(t, b, mailer, "support-owner-b@example.test")
	if status, out := b.do(t, "GET", "/api/v1/account", nil); status != 200 || out["account_id"] == id || out["account_id"] == nil {
		t.Fatal("accounts share identity")
	}
	if status, _ := a.do(t, "POST", "/api/v1/account/logout", nil); status != 200 {
		t.Fatal(status)
	}
	if status, out := a.do(t, "GET", "/api/v1/account", nil); status != 401 || out["account_id"] != nil {
		t.Fatal("logout still exposes identity")
	}
}
