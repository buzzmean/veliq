package clientservice

import (
	"net/netip"
	"testing"
	"time"

	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestGreaseECHYouTubeMediaOuterReachesLadderOnlyForYouTubeOnlyDNSSet(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	if !protectedBrowserDomain("chatgpt.com") {
		t.Fatal("fixture: chatgpt.com must be protected")
	}
	ip := netip.MustParseAddr("173.194.153.101")
	outer := "rr2---sn-u15hn5-50.googlevideo.com"
	evidence := func(outer string, names ...string) browserDomainEvidence {
		var index browserDomainIndex
		rows := []wp.DNSCacheEntry{}
		for _, n := range names {
			rows = append(rows, wp.DNSCacheEntry{Name: n, Address: ip.String(), TTL: 60})
		}
		index.replace(cur.network, rows, nil, time.Now())
		return index.profileEvidenceFor(cur.network, cur.profile.ID, ip, outer, time.Now(), func(h string) bool { return c.browserOriginPolicy(h).Kind != "" })
	}
	e := evidence(outer, outer, "rr2.sn-u15hn5-50.googlevideo.com")
	if e.Ambiguous || e.Domain != outer || e.YoutubeSubgroup != "googlevideo:sn-u15hn5-50" || e.Source != "ECH_YOUTUBE_MEDIA_OUTER_IN_DNS_SET" {
		t.Fatal("GREASE outer googlevideo stayed ambiguous", e)
	}
	q.Host, q.HintOnly, q.OriginAmbiguous = e.Domain, true, e.Ambiguous && !youtubeSameHintSubgroup(e)
	p.Destination = netip.AddrPortFrom(ip, 443)
	if !c.localLadderEligible(cur, q, p) {
		t.Fatal("YouTube media outer cannot reach the LOCAL ladder")
	}
	for name, names := range map[string][]string{
		"protected-shared": {outer, "chatgpt.com"},
		"other-site":       {outer, "www.google.com"},
		"outer-not-in-dns": {"rr2.sn-u15hn5-50.googlevideo.com", "rr5---sn-other.googlevideo.com"},
	} {
		if e := evidence(outer, names...); !e.Ambiguous || e.Source == "ECH_YOUTUBE_MEDIA_OUTER_IN_DNS_SET" {
			t.Fatal("ambiguity cleared", name, e)
		}
	}
	if e := evidence("redirector.googlevideo.com", "redirector.googlevideo.com", "rr2.sn-u15hn5-50.googlevideo.com"); e.Source == "ECH_YOUTUBE_MEDIA_OUTER_IN_DNS_SET" {
		t.Fatal("unclassified CDN host trusted", e)
	}
}
