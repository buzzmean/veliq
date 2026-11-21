package windowsplatform

import (
	"context"
	"time"
)

type NativeFirewallStatus struct {
	State               string    `json:"state"`
	Known               bool      `json:"known"`
	RulePresent         bool      `json:"rule_present"`
	ProgramMatches      bool      `json:"program_matches"`
	Effective           bool      `json:"effective"`
	LocalRulesPermitted bool      `json:"local_rules_permitted"`
	CheckedAt           time.Time `json:"checked_at"`
	Scope               string    `json:"scope"`
}

// Read-only diagnostic, never invoked by capture/OPEN or page planning. A failed
// query is UNKNOWN, not proof of a missing rule or a healthy native transport.
func InspectNativeFirewall(ctx context.Context) NativeFirewallStatus {
	bounded, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	out := inspectNativeFirewall(bounded)
	out.CheckedAt = time.Now().UTC()
	out.Scope = "installed service executable inbound TCP only; not proof of remote TLS/HTTP, not a crash deny guard"
	return out
}
