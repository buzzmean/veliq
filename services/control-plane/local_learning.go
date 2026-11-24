package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/buzzmean/veliq/core/locallearning"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/originpolicy"
	"github.com/buzzmean/veliq/core/security"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func (a *API) localLearning(w http.ResponseWriter, r *http.Request) {
	if a.Settings.LocalLearningFile == "" {
		a.fail(w, 503, "LOCAL_LEARNING_NOT_CONFIGURED")
		return
	}
	var req locallearning.Request
	if body(r, &req) != nil || !locallearning.ValidScope(req.Command.Scope) || req.Proof.RelayID != locallearning.Audience(req.Command) {
		a.fail(w, 400, "LOCAL_LEARNING_BOUND_PROOF_REQUIRED")
		return
	}
	d, e := a.Store.Device(r.Context(), req.Proof.DeviceID)
	if e != nil || d.Revoked {
		a.fail(w, 401, "LOCAL_LEARNING_DEVICE_UNAVAILABLE")
		return
	}
	key, e := security.DecodePublicKey(d.PublicKey)
	if e != nil || req.Proof.Verify(key, time.Now()) != nil {
		a.fail(w, 401, "LOCAL_LEARNING_PROOF_INVALID")
		return
	}
	if e = a.Store.ConsumeProof(r.Context(), req.Proof); e != nil {
		a.fail(w, 401, "LOCAL_LEARNING_PROOF_REPLAY_OR_REVOKED")
		return
	}
	peer, e := netip.ParseAddr(sourceKey(r))
	if e != nil {
		a.fail(w, 400, "LOCAL_LEARNING_PEER_INVALID")
		return
	}
	network, e := locallearning.Network(a.Settings.SigningKey.Seed(), peer)
	if e != nil {
		a.fail(w, 400, "LOCAL_LEARNING_PUBLIC_PEER_REQUIRED")
		return
	}
	owner := sha256.Sum256(key)
	a.localLearningMu.Lock()
	defer a.localLearningMu.Unlock()
	if a.learning == nil {
		a.learning, e = locallearning.New(a.Settings.LocalLearningFile)
		if e != nil {
			a.fail(w, 503, "LOCAL_LEARNING_STATE_UNAVAILABLE")
			return
		}
	}
	release, e := a.readLocalCatalog()
	if e != nil {
		a.fail(w, 503, "LOCAL_LEARNING_CATALOG_UNAVAILABLE")
		return
	}
	registry := originpolicy.Bundled()
	if release.Catalog.Origins != nil {
		registry = *release.Catalog.Origins
	}
	host := req.Command.Scope.Group
	if strings.HasPrefix(host, "googlevideo:") {
		host = "googlevideo.com"
	}
	if registry.Lookup(host).Kind != "DPI" {
		a.fail(w, 400, "LOCAL_LEARNING_REVIEWED_DPI_SCOPE_REQUIRED")
		return
	}
	plans, _ := release.Catalog.Compile()
	valid := func(id string) bool {
		for _, p := range plans {
			if p.ID == id {
				return true
			}
		}
		for _, p := range localstrategy.BrowserYouTubeCandidates() {
			if p.ID == id {
				return true
			}
		}
		return false
	}
	doc, e := a.learning.Apply(network, hex.EncodeToString(owner[:]), req.Command, valid, time.Now().UTC())
	if e != nil {
		a.fail(w, 409, "LOCAL_LEARNING_STATE_REJECTED")
		return
	}
	raw, e := security.Sign(locallearning.Domain, a.Settings.KeyID, a.Settings.SigningKey, doc)
	if e != nil {
		a.fail(w, 500, "LOCAL_LEARNING_SIGN_FAILED")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}
