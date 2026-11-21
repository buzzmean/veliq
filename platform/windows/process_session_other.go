//go:build !windows

package windowsplatform

func InteractiveProcess(uint32) bool { return false }
