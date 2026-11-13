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
	if k.Network == "" || k.Profile == "" || !youtubeCDN(k) || !e.valid() {
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
	return now.Before(r.endpointNegative[cdnEndpointKey{k, e, id}].Until)
}
func (r *youtubeRuntime) chooseEndpoint(k youtubeKey, e cdnEndpoint, now time.Time) (string, string) {
	stage, strategy, _ := r.chooseEndpointWithReason(k, e, now)
	return stage, strategy
}

func (r *youtubeRuntime) chooseEndpointWithReason(k youtubeKey, e cdnEndpoint, now time.Time) (string, string, string) {
	stage, id := r.choose(k, now)
	if stage == "LOCAL" {
		r.mu.Lock()
		bad := r.endpointBlockedLocked(k, id, e, now)
		r.mu.Unlock()
		if bad {
			return "RELAY", "", "LEARNED_STRATEGY_BLOCKED_FOR_ENDPOINT"
		}
		return stage, id, "LEARNED_LOCAL"
	}
	if stage == "RELAY" {
		r.mu.Lock()
		defer r.mu.Unlock()
		v := r.cache[k]
		if peer := r.peerStrategyLocked(k, now); peer != "" && !r.endpointBlockedLocked(k, peer, e, now) {
			r.selection.PeerProvisional++
			v.Reason = cdnPeerProvisionalReason
			if v.Stage == "" {
				v.Stage = "RELAY"
				v.Until = now.Add(youtubeLearnTTL)
			}
			r.cache[k] = v
			return "LOCAL", peer, cdnPeerProvisionalReason
		}
		return stage, id, "NO_LEARNED_ROUTE"
	}
	return stage, id, "LEARNED_DIRECT"
}
