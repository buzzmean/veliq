package clientservice

import (
	"strings"
	"time"
)

const cdnSiblingTTL = 30 * time.Second
const cdnSiblingLive = 5 * time.Second
const cdnDataTrialBytes = 64 * 1024

type relaySiblingEvidence struct {
	MediaRequired         bool
	MediaHost, MediaMatch string
	MediaBytes            uint64
	MediaAgeMS            int64
	Eligible              bool
	AgeMS                 int64
	Reason, Subgroup      string
	LastRX                time.Time
}

// A recent receiving tunnel may be closed/idle while Chrome opens its successor.
// This bounded history is not a guarantee of a concurrent playable relay segment.
func (u *browserRelayUsage) trialSibling(profile, network, subgroup string, now time.Time) relaySiblingEvidence {
	out := relaySiblingEvidence{AgeMS: -1, Reason: "NO_SCOPED_RELAY_MEDIA"}
	if network == "" {
		out.Reason = "NETWORK_UNKNOWN"
		return out
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	best := -1
	for _, v := range u.videos {
		group := youtubeSubgroup(v.Domain)
		if v.Profile != profile || v.Network != network || v.Port != 443 || !youtubeCDN(youtubeKey{Domain: group}) || v.Received <= cdnDataTrialBytes || v.LastRead.IsZero() || v.Failure != "" {
			continue
		}
		age := now.Sub(v.LastRead)
		if age < 0 {
			continue
		}
		eligible := age <= cdnSiblingTTL
		rank := 0
		if eligible {
			rank += 100
		}
		if group == subgroup {
			rank += 10
		}
		if rank < best || rank == best && out.AgeMS >= 0 && age.Milliseconds() >= out.AgeMS {
			continue
		}
		best = rank
		reason := "RELAY_ACTIVITY_EXPIRED"
		if eligible {
			reason = "RECENT_CDN_CLASS"
			if group == subgroup {
				reason = "RECENT_SAME_SUBGROUP"
			}
			if v.Closed.IsZero() && age < cdnSiblingLive {
				reason = "LIVE_CDN_CLASS"
				if group == subgroup {
					reason = "LIVE_SAME_SUBGROUP"
				}
			}
		}
		out = relaySiblingEvidence{Eligible: eligible, AgeMS: age.Milliseconds(), Reason: reason, Subgroup: group, LastRX: v.LastRead}
	}
	return out
}

// We cannot inspect an encrypted request before choosing its TLS route. Prefer
// a host/cluster that has already carried bulk RELAY data, never an rrN name.
func (u *browserRelayUsage) mediaTrialSibling(profile, network, host string, now time.Time) relaySiblingEvidence {
	peer := u.trialSibling(profile, network, youtubeSubgroup(host), now)
	peer.MediaRequired = true
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, v := range u.videos {
		if v.Profile != profile || v.Network != network || v.Port != 443 || v.Received <= cdnStrongBytes || v.Failure != "" || v.LastRead.IsZero() {
			continue
		}
		sameCluster := strings.HasPrefix(youtubeSubgroup(host), "googlevideo:sn-") && youtubeSubgroup(v.Domain) == youtubeSubgroup(host)
		if v.Domain != host && !sameCluster {
			continue
		}
		age := now.Sub(v.LastRead)
		if age < 0 || age > cdnSiblingTTL {
			continue
		}
		exact := v.Domain == host
		if peer.MediaBytes > 0 && (peer.MediaMatch == "EXACT_HOST" && !exact || (peer.MediaMatch == "EXACT_HOST") == exact && peer.MediaAgeMS <= age.Milliseconds()) {
			continue
		}
		peer.MediaHost = v.Domain
		peer.MediaBytes = v.Received
		peer.MediaAgeMS = age.Milliseconds()
		peer.MediaMatch = "SAME_SUBGROUP"
		if exact {
			peer.MediaMatch = "EXACT_HOST"
		}
	}
	return peer
}
