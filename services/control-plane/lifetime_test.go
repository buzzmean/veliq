package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/buzzmean/veliq/core/security"
	"testing"
	"time"
)

func TestLifetimeEntitlementHasNoDeadline(t *testing.T) {
	e := Entitlement{Managed: true, Lifetime: true}
	if !e.Active(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("perpetual grant expires")
	}
	s := statusFor(e, true, time.Now())
	if !s.Active || s.PaidUntil != nil || s.GraceUntil != nil {
		t.Fatal("fabricated payment deadline", s)
	}
	raw, _ := json.Marshal(s)
	var legacy controlclient.SubscriptionStatus
	if e := security.Parse(raw, &legacy); e != nil || !legacy.Active {
		t.Fatal("legacy strict client rejected response", e)
	}
	if (Entitlement{Managed: true}).Active(time.Now()) {
		t.Fatal("unpaid became active")
	}
}

func TestLifetimeAccountConnectCapacityAndRevocation(t *testing.T) {
	for _, kind := range []string{"player", "club"} {
		t.Run(kind, func(t *testing.T) {
			api, store, mail := accountAPI(t, true)
			owner := &call{api: api}
			login(t, owner, mail, kind+"@example.test")
			if st, _ := owner.do(t, "POST", "/api/v1/account/profile", map[string]string{"kind": kind, "name": "Lifetime fixture"}); st != 200 {
				t.Fatal(st)
			}
			seats := 1
			if kind == "club" {
				seats = 36
			}
			sub := linkedPlan(t, owner, kind, seats)
			ctx := context.Background()
			if _, e := store.DB.Exec(ctx, "UPDATE subscriptions SET lifetime=true,paid_until=NULL,auto_renew=false WHERE id=$1", sub); e != nil {
				t.Fatal(e)
			}
			if _, e := store.DB.Exec(ctx, "UPDATE activation_codes SET expires_at=now()-interval '1 day' WHERE subscription_id=$1", sub); e != nil {
				t.Fatal(e)
			}
			st, view := owner.do(t, "GET", "/api/v1/account", nil)
			if st != 200 {
				t.Fatal(st)
			}
			ss := view["subscriptions"].([]any)[0].(map[string]any)
			if ss["lifetime"] != true || ss["active"] != true || ss["can_connect"] != true || ss["paid_until"] != nil {
				t.Fatal("account view", ss)
			}
			var device string
			for i := 0; i <= seats; i++ {
				l, q, _ := newLinkRequest(t, "device", fmt.Sprintf("%064x", i+1))
				client := &call{api: api, ip: fmt.Sprintf("192.0.2.%d:12345", i+10)}
				if st, _ = client.do(t, "POST", "/api/v1/enroll/device/start", q); st != 201 {
					t.Fatal("start", i, st)
				}
				owner.ip = fmt.Sprintf("198.51.100.%d:12345", i+10)
				if st, _ = owner.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": sub}); st != 200 {
					t.Fatal("approve", i, st)
				}
				st, _ = client.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret})
				if i == seats {
					if st == 200 {
						t.Fatal("capacity exceeded")
					}
					break
				}
				if st != 200 {
					t.Fatal("enroll", i, st)
				}
				device = q.Device.DeviceID
			}
			ent, e := store.DeviceEntitlement(ctx, device)
			if e != nil || !ent.Lifetime || !ent.Active(time.Now()) {
				t.Fatal("device denied", e, ent)
			}
			cutoff, e := store.SubscriptionCutoff(ctx, time.Now().AddDate(100, 0, 0))
			if e != nil || len(cutoff) != 0 {
				t.Fatal("lifetime cutoff", e, cutoff)
			}
			if _, e = store.DB.Exec(ctx, "UPDATE accounts SET disabled=true WHERE id=(SELECT account_id FROM subscriptions WHERE id=$1)", sub); e != nil {
				t.Fatal(e)
			}
			ent, e = store.DeviceEntitlement(ctx, device)
			if e != nil || ent.Active(time.Now()) {
				t.Fatal("disabled account retained lifetime access", e, ent)
			}
			if _, e = store.DB.Exec(ctx, "UPDATE accounts SET disabled=false WHERE id=(SELECT account_id FROM subscriptions WHERE id=$1)", sub); e != nil {
				t.Fatal(e)
			}
			for _, query := range []string{"UPDATE activation_codes SET revoked=true WHERE subscription_id=$1", "UPDATE subscriptions SET lifetime=false WHERE id=$1"} {
				if _, e = store.DB.Exec(ctx, query, sub); e != nil {
					t.Fatal(e)
				}
				ent, e = store.DeviceEntitlement(ctx, device)
				if e != nil || ent.Active(time.Now()) {
					t.Fatal("revocation ineffective", e, ent)
				}
				if _, e = store.DB.Exec(ctx, "UPDATE activation_codes SET revoked=false WHERE subscription_id=$1", sub); e != nil {
					t.Fatal(e)
				}
			}
			var payments int
			if e = store.DB.QueryRow(ctx, "SELECT count(*) FROM payments").Scan(&payments); e != nil || payments != 0 {
				t.Fatal("fabricated payment", e, payments)
			}
		})
	}
}
