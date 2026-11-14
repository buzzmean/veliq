package clientservice

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

const cdnPeerProvisionalReason = "CDN_PEER_PROMOTED_PROVISIONAL"

// A real promoted CDN flow (strong running, completed burst or three sustained
// trials) on one sn-subgroup lets OTHER googlevideo subgroups of the same
// network/profile/hint mode open new TCP flows LOCAL with that exact strategy,
// without waiting for their own max1 trial. It is provisional: the flow is a
// normal LOCAL flow (first-flight fallback to RELAY before origin bytes, no
// replay), >64KiB confirms only its own subgroup, and a real CDN flow failure
// revokes the peer proof for the whole network/profile/strategy.
func (r *youtubeRuntime) notePeerProofLocked(k youtubeKey, strategy string, now time.Time) {
	if !youtubeCDN(k) || k.Network == "" || strategy == "" {
		return
	}
	if r.peerProofs == nil {
		r.peerProofs = map[youtubeQualification]time.Time{}
	}
	for q, until := range r.peerProofs {
		if !now.Before(until) {
			delete(r.peerProofs, q)
		}
	}
	q := youtubeQualification{k.Network, k.Profile, strategy, k.HintOnly}
	if _, exists := r.peerProofs[q]; !exists && len(r.peerProofs) >= 64 {
		return
	}
	r.peerProofs[q] = now.Add(youtubeLearnTTL)
	r.persistPeerLocked(q, now, true)
}

// Caller holds mu. Each confirmed (>64KiB, post-hello write, transform) real
// googlevideo LOCAL flow with a live peer strategy keeps that proof alive, so a
// long session does not fall back to RELAY 10 minutes after the first promotion.
// An expired proof is never revived here; it needs a new promotion.
func (r *youtubeRuntime) renewPeerProofLocked(k youtubeKey, strategy string, now time.Time) {
	if !youtubeCDN(k) || k.Network == "" {
		return
	}
	q := youtubeQualification{k.Network, k.Profile, strategy, k.HintOnly}
	if until, ok := r.peerProofs[q]; ok && now.Before(until) {
		r.peerProofs[q] = now.Add(youtubeLearnTTL)
		r.selection.PeerRenewals++
		r.persistPeerLocked(q, now, false)
	}
}

// Caller holds mu. Returns a strategy only for a CDN subgroup without its own
// LOCAL decision whose real flows have not failed with that strategy recently.
// Background public-origin checks (www/i.ytimg GET) are not CDN flow evidence
// and neither block nor revoke a peer proof.
func (r *youtubeRuntime) peerProofLocked(k youtubeKey, now time.Time) *cdnPeerEvidence {
	if !youtubeCDN(k) || k.Network == "" || len(r.peerProofs) == 0 || !r.room(k, now) {
		return nil
	}
	for _, id := range r.order {
		until := r.peerProofs[youtubeQualification{k.Network, k.Profile, id, k.HintOnly}]
		deniedUntil := r.peerDenied[youtubeScoreKey{k, id}]
		if now.Before(until) && !now.Before(deniedUntil) {
			return &cdnPeerEvidence{Strategy: id, Until: until, DeniedUntil: deniedUntil}
		}
	}
	return nil
}

// Caller holds mu. Only a real CDN flow failure counts; BACKGROUND_* reasons and
// non-CDN hosts (www/i.ytimg/account) never revoke CDN peer evidence.
func (r *youtubeRuntime) peerFlowFailedLocked(k youtubeKey, strategy, reason string, now time.Time) {
	if !youtubeCDN(k) || strategy == "" || strings.HasPrefix(reason, "BACKGROUND_") {
		return
	}
	q := youtubeQualification{k.Network, k.Profile, strategy, k.HintOnly}
	if now.Before(r.peerProofs[q]) {
		r.selection.PeerRevocations++
	}
	delete(r.peerProofs, q)
	if _, remembered := r.peerSeen[q]; remembered {
		r.persistPeerLocked(q, time.Time{}, true)
	}
	if r.peerDenied == nil {
		r.peerDenied = map[youtubeScoreKey]time.Time{}
	}
	for key, until := range r.peerDenied {
		if !now.Before(until) {
			delete(r.peerDenied, key)
		}
	}
	if len(r.peerDenied) < 256 {
		r.peerDenied[youtubeScoreKey{k, strategy}] = now.Add(youtubeLearnTTL)
	}
}

// Peer proofs survive service restarts for cdnPeerRememberTTL since their last
// promotion/renewal, so the FIRST googlevideo TCP of a new session on the same
// network/profile can already use the proven strategy instead of RELAY. A
// restored proof is an ordinary provisional peer proof (10 min, renewable);
// a real CDN flow failure revokes it and the file is rewritten.
const cdnPeerRememberTTL = 24 * time.Hour

type cdnPeerStored struct {
	Network  string    `json:"network"`
	Profile  string    `json:"profile"`
	Strategy string    `json:"strategy"`
	HintOnly bool      `json:"hint_only"`
	Seen     time.Time `json:"seen"`
}
type cdnPeerFile struct {
	Version int             `json:"version"`
	Proofs  []cdnPeerStored `json:"proofs"`
}

func (r *youtubeRuntime) configurePeerStore(path string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path == "" || r.peerPath == path {
		return
	}
	r.peerPath = path
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64*1024 {
		return
	}
	var f cdnPeerFile
	if json.Unmarshal(raw, &f) != nil || f.Version != 1 {
		return
	}
	if r.peerProofs == nil {
		r.peerProofs = map[youtubeQualification]time.Time{}
	}
	if r.peerSeen == nil {
		r.peerSeen = map[youtubeQualification]time.Time{}
	}
	for _, p := range f.Proofs {
		if p.Network == "" || p.Strategy == "" || now.Sub(p.Seen) > cdnPeerRememberTTL || p.Seen.After(now.Add(time.Minute)) || len(r.peerProofs) >= 64 {
			continue
		}
		q := youtubeQualification{p.Network, p.Profile, p.Strategy, p.HintOnly}
		r.peerProofs[q] = now.Add(youtubeLearnTTL)
		r.peerSeen[q] = p.Seen
		r.selection.PeerRestored++
	}
}

// Caller holds mu. Records when a proof was last proven and writes the file
// off-lock; renewals are rate-limited to one write per minute.
func (r *youtubeRuntime) persistPeerLocked(changed youtubeQualification, seen time.Time, force bool) {
	if r.peerSeen == nil {
		r.peerSeen = map[youtubeQualification]time.Time{}
	}
	if !seen.IsZero() {
		r.peerSeen[changed] = seen
	} else {
		delete(r.peerSeen, changed)
	}
	if r.peerPath == "" || !force && seen.Sub(r.peerWritten) < time.Minute {
		return
	}
	r.peerWritten = seen
	if seen.IsZero() {
		r.peerWritten = time.Now()
	}
	f := cdnPeerFile{Version: 1}
	for q, at := range r.peerSeen {
		if time.Since(at) <= cdnPeerRememberTTL {
			f.Proofs = append(f.Proofs, cdnPeerStored{q.Network, q.Profile, q.Strategy, q.HintOnly, at})
		}
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return
	}
	r.peerWriteSeq++
	seq, path := r.peerWriteSeq, r.peerPath
	go func() {
		r.peerWriteMu.Lock()
		defer r.peerWriteMu.Unlock()
		if seq <= r.peerWriteDone {
			return
		}
		r.peerWriteDone = seq
		_ = writeFileAtomic(path, raw)
	}()
}
