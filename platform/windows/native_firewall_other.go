//go:build !windows

package windowsplatform

import "context"

func inspectNativeFirewall(context.Context) NativeFirewallStatus {
	return NativeFirewallStatus{State: "UNSUPPORTED_PLATFORM"}
}
