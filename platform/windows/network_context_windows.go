//go:build windows

package windowsplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 32768 {
		return 0, fmt.Errorf("network diagnostics output limit")
	}
	return b.Buffer.Write(p)
}

func runPowerShell(ctx context.Context, script string) ([]byte, error) {
	started := time.Now()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var out, stderr limitedOutput
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s", describeRunFailure(ctx, err, time.Since(started), stderr.String()))
	}
	return bytes.TrimPrefix(out.Bytes(), []byte{239, 187, 191}), nil
}

// Background-only read-only queries. Never called by the packet path. Failure is
// reported as unknown, not as proof that no VPN/driver/user conflict exists.
func inspectNetwork(ctx context.Context, hostRoutes []netip.Addr) NetworkContext {
	extra := ""
	for _, a := range hostRoutes {
		if a.Is4() {
			extra += " -or $_.DestinationPrefix -eq '" + a.String() + "/32'"
		}
	}
	script := `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$a=@(Get-NetAdapter|Sort-Object InterfaceIndex|ForEach-Object{"$($_.InterfaceIndex):$($_.InterfaceGuid):$($_.Status):$($_.InterfaceDescription)"});
$a+=@(Get-NetIPAddress|Where-Object{$_.AddressState -eq 'Preferred'}|Sort-Object InterfaceIndex,IPAddress|ForEach-Object{"$($_.InterfaceIndex):$($_.IPAddress):$($_.PrefixLength)"});
$a+=@(Get-NetConnectionProfile|Sort-Object InterfaceIndex|ForEach-Object{"$($_.InterfaceIndex):$($_.Name):$($_.NetworkCategory)"});
$r=@(Get-NetRoute -PolicyStore ActiveStore|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0')` + extra + `}|Sort-Object InterfaceIndex,DestinationPrefix,NextHop|ForEach-Object{"$($_.InterfaceIndex):$($_.DestinationPrefix):$($_.NextHop):$($_.RouteMetric)"});
$d=@(Get-DnsClientServerAddress|Sort-Object InterfaceIndex,AddressFamily|ForEach-Object{"$($_.InterfaceIndex):$($_.AddressFamily):$($_.ServerAddresses -join ',')"});
$v=@(Get-NetAdapter|Where-Object{$_.Status -eq 'Up' -and ($_.InterfaceDescription+' '+$_.Name) -match 'VPN|Happ|TUN|TAP|WireGuard|Wintun'}|Sort-Object InterfaceIndex|ForEach-Object{$_.Name});
$proxy='HKCU is service account, not interactive user; WinHTTP: '+((netsh winhttp show proxy|Out-String).Trim());
$doh='browser Secure DNS unknown; system DoH cmdlet unavailable';if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){$doh='configured system DoH templates: '+@(Get-DnsClientDohServerAddress).Count+'; availability not probed'};
@{adapters=$a;routes=$r;dns=$d;vpn=$v;proxy=$proxy;secure_dns=$doh;egress='unmeasured'}|ConvertTo-Json -Depth 4 -Compress`
	raw, err := runPowerShell(ctx, script)
	if err != nil {
		return NetworkContext{Error: "read-only Windows network inspection unavailable: " + err.Error()}
	}
	var n NetworkContext
	if err := json.Unmarshal(raw, &n); err != nil {
		return NetworkContext{Error: "invalid Windows diagnostic snapshot"}
	}
	return n
}

func inspectConflicts(ctx context.Context) ConflictScan {
	script := `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$me=` + strconv.Itoa(os.Getpid()) + `;
$c=@(Get-Process|Where-Object{$_.Id -ne $me -and $_.ProcessName -match '^(winws|winws2|goodbyedpi)$'}|ForEach-Object{$_.ProcessName});
$anti=@(Get-Process|Where-Object{$_.ProcessName -match '^(easyanticheat.*|beservice.*|vgc|faceit.*)$'}|Select-Object -ExpandProperty ProcessName -Unique);
$unknown=$false;foreach($p in @(Get-Process|Where-Object{$_.Id -ne $me -and $_.Id -gt 4 -and $_.ProcessName -notmatch '^(TslGame|cs2|dota2|r5apex|VALORANT.*|FACEIT.*|beservice.*|easyanticheat.*|vgc)$'})){try{if(@($p.Modules|Where-Object{$_.ModuleName -ieq 'WinDivert.dll'}).Count -gt 0){$c+=($p.ProcessName+':WinDivert.dll')}}catch{$unknown=$true}};
@{conflicts=$c;anti_cheats=$anti;incomplete=$unknown}|ConvertTo-Json -Depth 3 -Compress`
	raw, err := runPowerShell(ctx, script)
	if err != nil {
		return ConflictScan{Error: "conflict scan unavailable: " + err.Error()}
	}
	var out struct {
		Conflicts  []string `json:"conflicts"`
		AntiCheats []string `json:"anti_cheats"`
		Incomplete bool     `json:"incomplete"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return ConflictScan{Error: "invalid conflict scan snapshot"}
	}
	return ConflictScan{Conflicts: out.Conflicts, AntiCheats: out.AntiCheats, Incomplete: out.Incomplete}
}
