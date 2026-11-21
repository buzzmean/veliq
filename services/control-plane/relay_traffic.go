package controlplane

import (
	"crypto/sha256"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/traffic"
	"net/http"
	"strings"
	"time"
)

func (a *API) relayTraffic(w http.ResponseWriter, r *http.Request) {
	if a.Settings.RelayTrafficFile == "" {
		a.fail(w, 503, "RELAY_TRAFFIC_NOT_CONFIGURED")
		return
	}
	a.relayTrafficMu.Lock()
	defer a.relayTrafficMu.Unlock()
	if a.traffic == nil {
		var e error
		a.traffic, e = traffic.NewMonth(a.Settings.RelayTrafficFile)
		if e != nil {
			a.fail(w, 503, "RELAY_TRAFFIC_STATE_UNAVAILABLE")
			return
		}
	}
	if r.Method == "POST" {
		var o traffic.Observation
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(token) != 32 || body(r, &o) != nil {
			a.fail(w, 401, "RELAY_TRAFFIC_AUTHORIZATION_REQUIRED")
			return
		}
		hash := sha256.Sum256([]byte(token))
		var valid bool
		if e := a.Store.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM relay_nodes WHERE id=$1 AND heartbeat_token_hash=$2)", o.Relay, hash[:]).Scan(&valid); e != nil || !valid {
			a.fail(w, 401, "RELAY_TRAFFIC_AUTHORIZATION_FAILED")
			return
		}
		limit := uint64(0)
		if o.Relay == "VPS-PRIMARY" {
			limit = 3000000000000
		}
		if e := a.traffic.Observe(o, limit, time.Now()); e != nil {
			a.fail(w, 400, "RELAY_TRAFFIC_OBSERVATION_REJECTED")
			return
		}
	} else if r.Method != "GET" {
		a.fail(w, 405, "method not allowed")
		return
	}
	now := time.Now().UTC()
	doc := traffic.Document{GeneratedAt: now, ExpiresAt: now.Add(5 * time.Minute), Relays: a.traffic.Snapshot(now), Scope: "sampled Linux NIC TX, UTC calendar month; includes non-relay traffic; partial coverage/provider billing reset day unknown; missing data never means zero usage"}
	raw, e := security.Sign(traffic.Domain, a.Settings.KeyID, a.Settings.SigningKey, doc)
	if e != nil {
		a.fail(w, 500, "RELAY_TRAFFIC_SIGN_FAILED")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}
