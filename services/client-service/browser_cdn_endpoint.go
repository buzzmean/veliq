package clientservice

import (
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"net/netip"
	"time"
)

type cdnEndpoint struct{ Host, Address string }

func (e cdnEndpoint) valid() bool {
	a, err := netip.ParseAddrPort(e.Address)
	return err == nil && a.Addr().Is4() && browserproxy.PublicDNSAddress(a.Addr()) && a.Port() == 443 && browserproxy.ValidPublicDNSName(e.Host)
}

type cdnEndpointKey struct {
	Scope    youtubeKey
	Endpoint cdnEndpoint
	Strategy string
}
type cdnEndpointFailure struct {
	Host, Address, Profile, Network, Strategy, Reason string
	Until                                             time.Time
}

func (r *youtubeRuntime) endpointFailed(k youtubeKey, id string, e cdnEndpoint, reason string, now time.Time) bool {
	if !youtubeCDN(k) {
		return false
	}
	return r.noteEndpointFailure(k, id, e, reason, now)
}

func (r *youtubeRuntime) noteEndpointFailure(k youtubeKey, id string, e cdnEndpoint, reason string, now time.Time) bool {
	if k.Network == "" || k.Profile == "" || !e.valid() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.endpointNegative == nil {
		r.endpointNegative = map[cdnEndpointKey]cdnEndpointFailure{}
	}
	for key, v := range r.endpointNegative {
		if !now.Before(v.Until) {
			delete(r.endpointNegative, key)
		}
	}
	if len(r.endpointNegative) >= 256 {
		var oldest cdnEndpointKey
		var until time.Time
		for key, v := range r.endpointNegative {
			if until.IsZero() || v.Until.Before(until) {
				oldest = key
				until = v.Until
			}
		}
		delete(r.endpointNegative, oldest)
	}
	r.endpointNegative[cdnEndpointKey{k, e, id}] = cdnEndpointFailure{e.Host, e.Address, k.Profile, k.Network, id, reason, now.Add(youtubeLearnTTL)}
	// No group score/reject/qualified reset: one endpoint is not evidence against
	// every host/IP in the sn-subgroup or this strategy on the whole network.
	return true
}
func (r *youtubeRuntime) endpointBlockedLocked(k youtubeKey, id string, e cdnEndpoint, now time.Time) bool {
	return r.endpointCheckLocked(k, id, e, now).Blocked
}

func (r *youtubeRuntime) endpointCheckLocked(k youtubeKey, id string, e cdnEndpoint, now time.Time) cdnEndpointCheck {
	until := r.endpointNegative[cdnEndpointKey{k, e, id}].Until
	return cdnEndpointCheck{Strategy: id, Blocked: now.Before(until), Until: until}
}
func (r *youtubeRuntime) chooseEndpoint(k youtubeKey, e cdnEndpoint, now time.Time) (string, string) {
	stage, strategy, _, _ := r.chooseEndpointWithReason(k, e, now)
	return stage, strategy
}

func (r *youtubeRuntime) chooseEndpointWithReason(k youtubeKey, e cdnEndpoint, now time.Time) (string, string, string, cdnSelectionEvidence) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, found := r.cache[k]
	stage, id := v.route(k.Network, now)
	evidence := cdnSelectionEvidence{CheckedAt: now.UTC(), Scope: k, Cache: cdnCacheSnapshot(v, found)}
	switch stage {
	case "LOCAL":
		check := r.endpointCheckLocked(k, id, e, now)
		evidence.Endpoint = &check
		if check.Blocked {
			return "RELAY", "", "LEARNED_STRATEGY_BLOCKED_FOR_ENDPOINT", evidence
		}
		return stage, id, "LEARNED_LOCAL", evidence
	case "RELAY":
		if peer := r.peerProofLocked(k, now); peer != nil {
			check := r.endpointCheckLocked(k, peer.Strategy, e, now)
			evidence.Peer, evidence.Endpoint = peer, &check
			if check.Blocked {
				return stage, id, "NO_LEARNED_ROUTE", evidence
			}
			r.selection.PeerProvisional++
			v.Reason = cdnPeerProvisionalReason
			if v.Stage == "" {
				v.Stage = "RELAY"
				v.Until = now.Add(youtubeLearnTTL)
			}
			r.cache[k] = v
			return "LOCAL", peer.Strategy, cdnPeerProvisionalReason, evidence
		}
		return stage, id, "NO_LEARNED_ROUTE", evidence
	default:
		return stage, id, "LEARNED_DIRECT", evidence
	}
}
