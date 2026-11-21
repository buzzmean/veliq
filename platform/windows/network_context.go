package windowsplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type NetworkContext struct {
	ObservedAt  time.Time `json:"observed_at"`
	Fingerprint string    `json:"fingerprint"`
	Adapters    []string  `json:"adapters"`
	Routes      []string  `json:"routes"`
	DNS         []string  `json:"dns"`
	Proxy       string    `json:"proxy"`
	SecureDNS   string    `json:"secure_dns"`
	Conflicts   []string  `json:"conflicts"`
	VPN         []string  `json:"vpn"`
	Error       string    `json:"error,omitempty"`
	Egress      string    `json:"egress"`
	// Conflict scan is slower than the route fingerprint and runs separately. A zero
	// time means no scan has succeeded yet: Conflicts is then unknown, not clean.
	AntiCheats          []string  `json:"anti_cheats,omitempty"`
	ConflictsObservedAt time.Time `json:"conflicts_observed_at,omitempty"`
	ConflictScan        string    `json:"conflict_scan,omitempty"`
}

// ConflictScan is the result of the process/module scan for known DPI tools,
// anti-cheat services and foreign WinDivert users.
type ConflictScan struct {
	AntiCheats []string // Presence alone is not evidence of an overlapping packet interceptor.
	ObservedAt time.Time
	Conflicts  []string
	Incomplete bool
	Error      string
}

// InspectNetwork builds the route fingerprint. hostRoutes are IPv4 addresses (for
// example relay VPS) whose /32 routes are included alongside the default routes.
func InspectNetwork(ctx context.Context, hostRoutes []netip.Addr) NetworkContext {
	n := inspectNetwork(ctx, hostRoutes)
	if n.Error != "" {
		return n
	}
	b, _ := json.Marshal(struct {
		A, R, D, V []string
		P          string
	}{n.Adapters, n.Routes, n.DNS, n.VPN, n.Proxy})
	s := sha256.Sum256(b)
	n.Fingerprint = hex.EncodeToString(s[:])
	n.ObservedAt = time.Now()
	n.Egress = "DIRECT follows current Windows routing (may be VPN); physical/VPN/relay public source requires endpoint proof"
	return n
}

// InspectConflicts scans processes and loaded modules. It is slow and never part of
// the route fingerprint; failure means "unknown", not "no conflict".
func InspectConflicts(ctx context.Context) ConflictScan {
	scan := inspectConflicts(ctx)
	if scan.Error == "" {
		scan.ObservedAt = time.Now()
	}
	return scan
}

// describeRunFailure turns an opaque child-process error into evidence. On Windows
// a context kill surfaces as "exit status 1", so the timeout flag is reported
// separately. stderr is bounded and stripped of control characters.
func describeRunFailure(ctx context.Context, err error, elapsed time.Duration, stderr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%v after %s", err, elapsed.Round(time.Millisecond))
	if ctx.Err() != nil {
		fmt.Fprintf(&b, " (%v: query budget exceeded)", ctx.Err())
	}
	clean := strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return ' '
		}
		return r
	}, stderr)
	clean = strings.Join(strings.Fields(clean), " ")
	if len(clean) > 300 {
		clean = clean[:300] + "..."
	}
	if clean != "" {
		fmt.Fprintf(&b, "; stderr: %s", clean)
	}
	return b.String()
}
