//go:build !windows

package clientservice

import (
	"context"
	"errors"
	"net"
)

func dialPolicyWatchdog(context.Context) (net.Conn, error) {
	return nil, errors.New("WINDOWS_REQUIRED")
}

func recoverPolicyWatchdog(Manifest, string, *policyWatchdogRecovery) error { return nil }
