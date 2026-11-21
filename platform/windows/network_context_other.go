//go:build !windows

package windowsplatform

import (
	"context"
	"net/netip"
)

func inspectNetwork(context.Context, []netip.Addr) NetworkContext {
	return NetworkContext{Error: "Windows network context unavailable; AUTO local learning disabled"}
}
func inspectConflicts(context.Context) ConflictScan {
	return ConflictScan{Error: "Windows conflict scan unavailable"}
}
