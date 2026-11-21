package windowsplatform

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"
)

// DNSCacheEntry is an OS resolver observation, not proof of a browser's hidden
// ECH name. No PTR lookup, packets, payload or system DNS settings are changed.
type DNSCacheEntry struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	TTL     uint32 `json:"ttl"`
}

func parseDNSCache(raw []byte) ([]DNSCacheEntry, error) {
	if len(raw) > 32768 {
		return nil, errors.New("DNS_CACHE_OUTPUT_LIMIT")
	}
	var rows []DNSCacheEntry
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, errors.New("DNS_CACHE_INVALID_JSON")
	}
	if len(rows) > 256 {
		return nil, errors.New("DNS_CACHE_ROW_LIMIT")
	}
	out := make([]DNSCacheEntry, 0, len(rows))
	for _, r := range rows {
		r.Name = strings.ToLower(strings.TrimSuffix(r.Name, "."))
		ip, err := netip.ParseAddr(r.Address)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || r.TTL == 0 || len(r.Name) > 253 || !strings.Contains(r.Name, ".") || strings.ContainsAny(r.Name, " /\\\r\n\t") {
			continue
		}
		r.Address = ip.Unmap().String()
		// Never extend the OS TTL; additionally bound observation lifetime.
		if time.Duration(r.TTL)*time.Second > 5*time.Minute {
			r.TTL = 300
		}
		out = append(out, r)
	}
	return out, nil
}
