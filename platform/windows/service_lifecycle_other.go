//go:build !windows

package windowsplatform

func BrowserRecoveryServiceState() string { return "UNKNOWN" }
