//go:build windows

package windowsplatform

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"strings"
)

//go:embed native_firewall_probe.ps1
var nativeFirewallProbe string

func inspectNativeFirewall(ctx context.Context) NativeFirewallStatus {
	path, err := os.Executable()
	if err != nil {
		return NativeFirewallStatus{State: "UNKNOWN_EXECUTABLE"}
	}
	script := "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ProgressPreference='SilentlyContinue';" + nativeFirewallProbe + "\nGet-VeliqNativeFirewallSnapshot '" + strings.ReplaceAll(path, "'", "''") + "' | ConvertTo-Json -Compress"
	raw, err := runPowerShell(ctx, script)
	if err != nil {
		state := "UNKNOWN_QUERY_FAILED"
		if ctx.Err() != nil {
			state = "UNKNOWN_QUERY_TIMEOUT"
		}
		return NativeFirewallStatus{State: state}
	}
	var out NativeFirewallStatus
	if json.Unmarshal(raw, &out) != nil || !out.Known {
		return NativeFirewallStatus{State: "UNKNOWN_INVALID_SNAPSHOT"}
	}
	switch out.State {
	case "APPLIED", "MISSING", "AMBIGUOUS_RULE", "FOREIGN_RULE", "RULE_NOT_EFFECTIVE", "SCOPE_MISMATCH", "LOCAL_RULES_FORBIDDEN_BY_POLICY":
		return out
	}
	return NativeFirewallStatus{State: "UNKNOWN_INVALID_SNAPSHOT"}
}
