package clientservice

import (
	"github.com/buzzmean/neexitlag/core/browserproxy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"sort"
	"time"
)

type browserAuthorityView struct {
	State            string                  `json:"state"`
	Reason           string                  `json:"reason,omitempty"`
	Applied          bool                    `json:"system_pac_applied"`
	AppliedAt        time.Time               `json:"applied_at"`
	ChromeRequests   int                     `json:"chrome_requests"`
	EdgeRequests     int                     `json:"edge_requests"`
	ChromeExchanges  int                     `json:"chrome_exchanges"`
	EdgeExchanges    int                     `json:"edge_exchanges"`
	OtherRequests    int                     `json:"other_application_requests"`
	FallbackRequests int                     `json:"safe_fallback_requests"`
	Profiles         []authorityProfileProof `json:"profiles"`
	ExistingTCP      string                  `json:"existing_tcp"`
	RawTLS           string                  `json:"raw_tls"`
}
type authorityProfileProof struct {
	Profile   string `json:"profile_id"`
	Requests  int    `json:"requests"`
	Exchanges int    `json:"exchanges"`
}

func (c *Controller) authorityStatus() browserAuthorityView {
	a := &c.browser.authority
	s := a.published.Load()
	v := browserAuthorityView{State: "AUTHORITY_PENDING", ExistingTCP: "PINNED_UNTIL_CLOSED", RawTLS: "DEGRADED_AUTHENTICATED_RELAY_WITHOUT_AUTHORITY"}
	if s == nil {
		return v
	}
	v.Reason = s.reason
	v.Applied = s.applied
	v.AppliedAt = s.appliedAt
	if time.Since(s.verifiedAt) > 15*time.Second {
		v.Applied = false
		v.Reason = "OWNER_PROXY_VERIFICATION_EXPIRED"
		return v
	}
	if s.server == nil {
		return v
	}
	snapshot := s.server.Snapshot()
	if !snapshot.Listening {
		v.State = "AUTHORITY_LISTENER_UNAVAILABLE"
		return v
	}
	var records []browserproxy.Record = snapshot.Records
	proofs := map[string]authorityProfileProof{}
	network := ""
	if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second {
		network = n.Fingerprint
	}
	for _, r := range records {
		if !s.applied || r.Started.Before(s.appliedAt) || r.Plan.Network != network || !r.Active && time.Since(r.Started) > 45*time.Second {
			continue
		}
		if !wp.IsCurrent(browserIdentity(browserproxy.Request{Owner: r.Owner})) {
			continue
		}
		p, ok := c.matchApplication(browserIdentity(browserproxy.Request{Owner: r.Owner}))
		if !ok || p.ID != r.Owner.Profile || !nativeBrowserProfile(p) {
			v.OtherRequests++
			continue
		}
		proof := proofs[p.ID]
		proof.Profile = p.ID
		proof.Requests++
		if r.Sent > 0 && r.Received > 0 {
			proof.Exchanges++
		}
		proofs[p.ID] = proof
		if edgeProfile(p) {
			v.EdgeRequests++
			if r.Sent > 0 && r.Received > 0 {
				v.EdgeExchanges++
			}
		} else {
			v.ChromeRequests++
			if r.Sent > 0 && r.Received > 0 {
				v.ChromeExchanges++
			}
		}
	}
	for _, proof := range proofs {
		v.Profiles = append(v.Profiles, proof)
	}
	sort.Slice(v.Profiles, func(i, j int) bool { return v.Profiles[i].Profile < v.Profiles[j].Profile })
	if s.fallback != nil {
		for _, r := range s.fallback.Snapshot().Records {
			if s.applied && !r.Started.Before(s.appliedAt) && (r.Active || time.Since(r.Started) <= 45*time.Second) {
				v.FallbackRequests++
			}
		}
	}
	if s.applied {
		v.State = "AUTHORITY_PAC_APPLIED_UPTAKE_PENDING"
	}
	if v.ChromeRequests+v.EdgeRequests > 0 {
		v.State = "AUTHORITY_REQUEST_OBSERVED"
	}
	return v
}
