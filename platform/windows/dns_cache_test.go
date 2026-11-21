package windowsplatform

import (
	"strings"
	"testing"
)

func TestDNSCacheSnapshotParsingTTLAndInvalidEntries(t *testing.T) {
	raw := []byte(`[{"name":"VK.RU.","address":"87.240.137.208","ttl":600},{"name":"chatgpt.com","address":"104.18.1.2","ttl":20},{"name":"expired.com","address":"8.8.8.8","ttl":0},{"name":"lan.local","address":"192.168.1.1","ttl":30},{"name":"bad/path","address":"8.8.8.8","ttl":30}]`)
	rows, err := parseDNSCache(raw)
	if err != nil || len(rows) != 2 || rows[0].Name != "vk.ru" || rows[0].TTL != 300 || rows[1].TTL != 20 {
		t.Fatal(rows, err)
	}
	if _, err = parseDNSCache([]byte(strings.Repeat(" ", 32769))); err == nil {
		t.Fatal("output limit")
	}
	if _, err = parseDNSCache([]byte(`{"error":"x"}`)); err == nil {
		t.Fatal("invalid shape")
	}
}
func TestECHOuterMetadataPreservedWithoutClaimingInnerSNI(t *testing.T) {
	initial := Decision{ResolveDomain: func(domain string) Decision {
		if domain != "" {
			t.Fatal("outer passed as authenticated SNI")
		}
		return Decision{}
	}}
	d := ResolveDeferredDecision(initial, "web.telegram.org", "ECH_OUTER_SNI_ONLY")
	if d.OuterSNI != "web.telegram.org" || d.OriginDomain != "" {
		t.Fatal(d)
	}
}
