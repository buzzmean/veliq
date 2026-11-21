//go:build windows

package windowsplatform

import "context"

func ReadDNSCache(ctx context.Context) ([]DNSCacheEntry, error) {
	// Background only. A bounded OS cache snapshot cannot see browser-private DoH
	// or prove which process asked a question. Do not pretend otherwise.
	raw, err := runPowerShell(ctx, `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$rows=@(Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | Select-Object -First 256 | ForEach-Object { @{name=[string]$_.Entry;address=[string]$_.Data;ttl=[uint32]$_.TimeToLive} });ConvertTo-Json -InputObject $rows -Compress`)
	if err != nil {
		return nil, err
	}
	return parseDNSCache(raw)
}
