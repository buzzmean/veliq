package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"github.com/buzzmean/neexitlag/core/security"
)

func linkedPlan(t *testing.T, c *call, kind string, seats int) string {
	t.Helper()
	code, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": kind + "-month", "seats": seats})
	if code != 201 {
		t.Fatal("create subscription", code)
	}
	id := out["id"].(string)
	if _, e := c.api.Store.DB.Exec(context.Background(), "UPDATE subscriptions SET paid_until=now()+interval '30 days' WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	return id
}
func newLinkRequest(t *testing.T, mode, machine string) (enrollment.DeviceLink, enrollment.DeviceLinkRequest, ed25519.PrivateKey) {
	t.Helper()
	l, e := enrollment.NewDeviceLink(mode)
	if e != nil {
		t.Fatal(e)
	}
	var key ed25519.PrivateKey
	var device freshpc.Request
	if mode == "device" {
		_, key, _ = ed25519.GenerateKey(rand.Reader)
		id, _ := security.NewID()
		device, e = enrollment.NewRequest(id, machine, key)
		if e != nil {
			t.Fatal(e)
		}
	}
	q, e := l.Request("Test lab PC", device, key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return l, q, key
}
func decodeLinkStatus(t *testing.T, out map[string]any) enrollment.DeviceLinkStatus {
	t.Helper()
	raw, _ := json.Marshal(out)
	var s enrollment.DeviceLinkStatus
	if json.Unmarshal(raw, &s) != nil {
		t.Fatal("malformed link status")
	}
	return s
}
func TestAccountDeviceBindingWithoutManualActivationCode(t *testing.T) {
	api, store, mail := accountAPI(t, false)
	owner := &call{api: api}
	login(t, owner, mail, "owner@example.test")
	if code, _ := owner.do(t, "POST", "/api/v1/account/profile", map[string]string{"kind": "player", "name": "Player"}); code != 200 {
		t.Fatal("profile", code)
	}
	sub := linkedPlan(t, owner, "player", 1)
	l, q, _ := newLinkRequest(t, "device", strings.Repeat("b", 64))
	client := &call{api: api, ip: "192.0.2.10:12345"}
	code, out := client.do(t, "POST", "/api/v1/enroll/device/start", q)
	if code != 201 {
		t.Fatal("start", code)
	}
	start := decodeLinkStatus(t, out)
	if start.VerificationURL != testOrigin+"/account.html#device="+l.ID || strings.Contains(start.VerificationURL, l.Secret) {
		t.Fatal("verification URL leaked credentials or changed origin")
	}
	if code, _ = client.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret}); code != 202 {
		t.Fatal("enrolled without browser approval", code)
	}
	bad, _ := enrollment.NewDeviceLink("device")
	if code, _ = client.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: bad.Secret}); code != 401 {
		t.Fatal("wrong poll credential", code)
	}
	stranger := &call{api: api, ip: "192.0.2.11:12345"}
	login(t, stranger, mail, "other@example.test")
	foreign := linkedPlan(t, stranger, "player", 1)
	if code, _ = owner.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": foreign}); code != 403 {
		t.Fatal("foreign subscription approved", code)
	}
	if code, _ = owner.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": sub}); code != 200 {
		t.Fatal("approval", code)
	}
	if code, _ = stranger.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": foreign}); code != 403 {
		t.Fatal("approved link stolen by another account", code)
	}
	code, out = client.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret})
	if code != 200 {
		t.Fatal("poll approved", code)
	}
	result := decodeLinkStatus(t, out)
	roots := x509.NewCertPool()
	roots.AddCert(api.Settings.CA)
	if result.Enrollment == nil || enrollment.ValidateEnrollmentResponse(*result.Enrollment, q.Device, roots) != nil || result.Account.Kind != "player" || result.Account.Subscription != sub {
		t.Fatal("invalid enrollment/account binding")
	}
	var seats int
	if e := store.DB.QueryRow(context.Background(), "SELECT count(*) FROM activation_slots WHERE device_id=$1", q.Device.DeviceID).Scan(&seats); e != nil || seats != 1 {
		t.Fatal("seat count", e, seats)
	}
	var wg sync.WaitGroup
	errors := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			caller := &call{api: api, ip: fmt.Sprintf("192.0.2.%d:12345", 20+i)}
			status, _ := caller.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret})
			if status != 200 {
				errors <- status
			}
		}(i)
	}
	wg.Wait()
	close(errors)
	for status := range errors {
		t.Fatal("lost response retry failed", status)
	}
	second, req, _ := newLinkRequest(t, "device", strings.Repeat("c", 64))
	if code, _ = client.do(t, "POST", "/api/v1/enroll/device/start", req); code != 201 {
		t.Fatal(code)
	}
	if code, _ = owner.do(t, "POST", "/api/v1/account/device-links/"+second.ID+"/approve", map[string]string{"subscription_id": sub}); code != 200 {
		t.Fatal(code)
	}
	if code, out = client.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: second.ID, Secret: second.Secret}); code != 403 || out["error"] != "ACTIVATION_LIMIT" {
		t.Fatal("seat limit bypassed", code)
	}
	if code, out = owner.do(t, "GET", "/api/v1/account", nil); code != 200 || out["kind"] != "player" || out["name"] != "Player" {
		t.Fatal("account type absent", code)
	}
}
func TestClubImageApprovalAndFreezeDoNotCloneDeviceKeys(t *testing.T) {
	api, store, mail := accountAPI(t, false)
	owner := &call{api: api}
	login(t, owner, mail, "club@example.test")
	if code, _ := owner.do(t, "POST", "/api/v1/account/profile", map[string]string{"kind": "club", "name": "Test Club"}); code != 200 {
		t.Fatal(code)
	}
	sub := linkedPlan(t, owner, "club", 1)
	l, q, _ := newLinkRequest(t, "image", "")
	client := &call{api: api}
	if code, _ := client.do(t, "POST", "/api/v1/enroll/device/start", q); code != 201 {
		t.Fatal(code)
	}
	if code, _ := owner.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": sub}); code != 200 {
		t.Fatal(code)
	}
	code, out := client.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret})
	if code != 200 {
		t.Fatal(code)
	}
	status := decodeLinkStatus(t, out)
	if status.BootstrapID != l.ID || status.Enrollment != nil || status.Account.Kind != "club" {
		t.Fatal("image approval included a device identity")
	}
	var count int
	if e := store.DB.QueryRow(context.Background(), "SELECT count(*) FROM devices").Scan(&count); e != nil || count != 0 {
		t.Fatal("template enrolled before first real boot", e, count)
	}
	roots := x509.NewCertPool()
	roots.AddCert(api.Settings.CA)
	for i := 0; i < 5; i++ {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		id, _ := security.NewID()
		device, e := enrollment.NewRequest(id, strings.Repeat("d", 64), key)
		if e != nil {
			t.Fatal(e)
		}
		proof, e := (enrollment.DeviceLink{ID: l.ID, Secret: l.BootstrapSecret, Mode: "device"}).Request("club-boot", device, key, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		code, out = client.do(t, "POST", "/api/v1/enroll/club", proof)
		if code != 201 {
			t.Fatal("freeze re-enrollment", i, code)
		}
		raw, _ := json.Marshal(out)
		var reply enrollment.Response
		json.Unmarshal(raw, &reply)
		if e = enrollment.ValidateEnrollmentResponse(reply, device, roots); e != nil {
			t.Fatal("certificate not bound to new key", e)
		}
	}
	if e := store.DB.QueryRow(context.Background(), "SELECT count(*) FROM activation_slots WHERE NOT disabled").Scan(&count); e != nil || count != 1 {
		t.Fatal("freeze consumed extra seats", e, count)
	}
	if code, _ = owner.do(t, "POST", "/api/v1/account/club-images/"+l.ID+"/revoke", map[string]any{}); code != 200 {
		t.Fatal("revoke image", code)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := security.NewID()
	device, _ := enrollment.NewRequest(id, strings.Repeat("d", 64), key)
	proof, _ := (enrollment.DeviceLink{ID: l.ID, Secret: l.BootstrapSecret, Mode: "device"}).Request("club-boot", device, key, time.Now())
	if code, _ = client.do(t, "POST", "/api/v1/enroll/club", proof); code != 403 {
		t.Fatal("revoked image still enrolls", code)
	}
}
func TestDeviceLinkRejectsReplacedCSRExpiredAndWrongAccountType(t *testing.T) {
	api, store, mail := accountAPI(t, false)
	owner := &call{api: api}
	login(t, owner, mail, "player@example.test")
	sub := linkedPlan(t, owner, "player", 1)
	l, q, _ := newLinkRequest(t, "device", strings.Repeat("e", 64))
	bad := q
	bad.Device.MachineHash = strings.Repeat("f", 64)
	if code, _ := owner.do(t, "POST", "/api/v1/enroll/device/start", bad); code != 400 {
		t.Fatal("signature substitution", code)
	}
	if code, _ := owner.do(t, "POST", "/api/v1/enroll/device/start", q); code != 201 {
		t.Fatal(code)
	}
	if _, e := store.DB.Exec(context.Background(), "UPDATE account_device_links SET expires_at=now()-interval '1 second' WHERE id=$1", l.ID); e != nil {
		t.Fatal(e)
	}
	if code, _ := owner.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret}); code != 410 {
		t.Fatal("expired link accepted", code)
	}
	image, req, _ := newLinkRequest(t, "image", "")
	if code, _ := owner.do(t, "POST", "/api/v1/enroll/device/start", req); code != 201 {
		t.Fatal(code)
	}
	if code, _ := owner.do(t, "POST", "/api/v1/account/device-links/"+image.ID+"/approve", map[string]string{"subscription_id": sub}); code != 403 {
		t.Fatal("player subscription authorized club image", code)
	}
}

func TestCodeFreeAccountRequiresPaymentEvenWhenLegacyEnforcementIsOff(t *testing.T) {
	api, store, mail := accountAPI(t, false)
	owner := &call{api: api}
	login(t, owner, mail, "unpaid@example.test")
	code, out := owner.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": 1})
	if code != 201 {
		t.Fatal(code)
	}
	sub := out["id"].(string)
	l, q, _ := newLinkRequest(t, "device", strings.Repeat("f", 64))
	if code, _ = owner.do(t, "POST", "/api/v1/enroll/device/start", q); code != 201 {
		t.Fatal(code)
	}
	if code, _ = owner.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": sub}); code != 403 {
		t.Fatal("unpaid registration obtained relay access", code)
	}
	var devices int
	if e := store.DB.QueryRow(context.Background(), "SELECT count(*) FROM devices").Scan(&devices); e != nil || devices != 0 {
		t.Fatal("unpaid account created device", e, devices)
	}
}
