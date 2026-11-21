//go:build !windows

package windowsplatform

import (
	"context"
	"errors"
)

func ReadDNSCache(context.Context) ([]DNSCacheEntry, error) {
	return nil, errors.New("DNS_CACHE_WINDOWS_ONLY")
}
