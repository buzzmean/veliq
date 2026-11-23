//go:build !windows

package windowsplatform

func verifyLanGameOwner(ProcessIdentity) bool { return false }
