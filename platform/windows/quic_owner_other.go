//go:build !windows

package windowsplatform

func quicOwnerClock() (int64, int64)                       { return 0, 0 }
func CurrentQUICProcessOwner(ProcessIdentity, string) bool { return false }
