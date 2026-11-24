package clientservice

import (
	"github.com/buzzmean/veliq/core/browserproxy"
	wp "github.com/buzzmean/veliq/platform/windows"
	"sort"
	"strings"
	"time"
)

type browserAuthorityView struct {
	Listeners       []authorityListenerView `json:"listeners"`
	State           string                  `json:"state"`
	Reason          string                  `json:"reason,omitempty"`
	Applied         bool                    `json:"system_proxy_applied"`
	AppliedAt       time.Time               `json:"applied_at"`
	ChromeRequests  int                     `json:"chrome_requests"`
	EdgeRequests    int                     `json:"edge_requests"`
	ChromeExchanges int                     `json:"chrome_exchanges"`
	EdgeExchanges   int                     `json:"edge_exchanges"`
	OtherRequests   int                     `json:"other_application_requests"`
	Profiles        []authorityProfileProof `json:"profiles"`
	ExistingTCP     string                  `json:"existing_tcp"`
	RawTLS          string                  `json:"raw_tls"`
}

type authorityListenerPublished struct {
	Role, Address, Error string
	Server               *browserproxy.Server
}
type authorityListenerView struct {
	Role              string                 `json:"role"`
	Address           string                 `json:"address"`
	Listening         bool                   `json:"listening"`
	Error             string                 `json:"error,omitempty"`
	ActiveConnections int                    `json:"active_connections"`
	Failures          map[string]uint64      `json:"failures"`
	Lost              uint64                 `json:"lost"`
	Truncated         bool                   `json:"truncated"`
	Requests          []authorityRequestView `json:"requests"`
}
type authorityRequestView struct {
	PID      uint32    `json:"pid"`
	Birth    uint64    `json:"creation_time"`
	Exe      string    `json:"exe"`
	Profile  string    `json:"profile_id"`
	Domain   string    `json:"domain"`
	Port     uint16    `json:"port"`
	Started  time.Time `json:"started_at"`
	Active   bool      `json:"active"`
	Result   string    `json:"result"`
	Sent     uint64    `json:"sent_bytes"`
	Received uint64    `json:"received_bytes"`
}

func authorityListenerSnapshot(p authorityListenerPublished) (authorityListenerView, []browserproxy.Record) {
	v := authorityListenerView{Role: p.Role, Address: p.Address, Error: p.Error, Requests: []authorityRequestView{}}
	if p.Server == nil {
		return v, nil
	}
	s := p.Server.Snapshot()
	v.Listening, v.ActiveConnections, v.Failures, v.Lost, v.Truncated = s.Listening, s.ActiveConnections, s.Failures, s.Lost, s.Truncated
	records := append([]browserproxy.Record(nil), s.Records...)
	sort.Slice(records, func(i, j int) bool { return records[i].Started.After(records[j].Started) })
	if len(records) > 4 {
		records = records[:4]
		v.Truncated = true
	}
	for _, r := range records {
		exe := r.Owner.Exe[strings.LastIndexAny(r.Owner.Exe, `/\`)+1:]
		v.Requests = append(v.Requests, authorityRequestView{PID: r.Owner.PID, Birth: r.Owner.Birth, Exe: exe, Profile: r.Owner.Profile, Domain: r.Domain, Port: r.Port, Started: r.Started, Active: r.Active, Result: r.Result, Sent: r.Sent, Received: r.Received})
	}
	return v, s.Records
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
	listeners := s.listeners
	if len(listeners) == 0 && s.server != nil {
		listeners = []authorityListenerPublished{{Role: "primary", Address: s.server.Address(), Server: s.server}}
	}
	var records []browserproxy.Record
	for _, listener := range listeners {
		view, current := authorityListenerSnapshot(listener)
		v.Listeners = append(v.Listeners, view)
		records = append(records, current...)
	}
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
	if s.applied {
		v.State = "AUTHORITY_PROXY_APPLIED_UPTAKE_PENDING"
	}
	if v.ChromeRequests+v.EdgeRequests > 0 {
		v.State = "AUTHORITY_REQUEST_OBSERVED"
	}
	return v
}
