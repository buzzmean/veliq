package clientservice

import (
	"net/netip"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

func TestHTTP80AdmissionPreservesSecurityAndProtocolScopes(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host, q.Port, q.Secure, q.Ingress, q.Source = "www.youtube.com", 80, false, "NATIVE_TCP", netip.MustParseAddrPort("127.0.0.1:50101")
	p.Destination = netip.MustParseAddrPort("74.125.111.131:80")
	if !c.http80Eligible(cur, q, p) {
		t.Fatal("explicit native HTTP80 DPI scope rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*profilesResult, *browserproxy.Request, *browserproxy.Plan)
	}{
		{"TLS", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.Secure = true }},
		{"443", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.Port = 443 }},
		{"protected", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.Host = "api.openai.com" }},
		{"relay-first", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.Host = "web.telegram.org" }},
		{"ordinary", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.Host = "vk.ru" }},
		{"hint", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.HintOnly = true }},
		{"ambiguous", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.OriginAmbiguous = true }},
		{"PAC", func(_ *profilesResult, q *browserproxy.Request, _ *browserproxy.Plan) { q.Ingress = "PAC_CONNECT" }},
		{"LAN", func(_ *profilesResult, _ *browserproxy.Request, p *browserproxy.Plan) {
			p.Destination = netip.MustParseAddrPort("192.168.1.1:80")
		}},
		{"OFF", func(c *profilesResult, _ *browserproxy.Request, _ *browserproxy.Plan) { c.enabled = false }},
		{"DIRECT profile", func(c *profilesResult, _ *browserproxy.Request, _ *browserproxy.Plan) {
			c.profile.Mode = profiles.Direct
		}},
		{"explicit", func(c *profilesResult, _ *browserproxy.Request, _ *browserproxy.Plan) {
			c.profile.Rules = []flowpolicy.Rule{{ID: "blocked", Domains: []string{"www.youtube.com"}, Action: flowpolicy.Block}}
		}},
		{"different-network", func(_ *profilesResult, _ *browserproxy.Request, p *browserproxy.Plan) { p.Network = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh, request, plan := cur, q, p
			tc.mutate(&fresh, &request, &plan)
			if c.http80Eligible(fresh, request, plan) {
				t.Fatal("HTTP80 admission escaped scope")
			}
		})
	}
	if c.localLadderEligible(cur, q, p) {
		t.Fatal("HTTP80 proof entered TLS/CDN ladder")
	}
}
