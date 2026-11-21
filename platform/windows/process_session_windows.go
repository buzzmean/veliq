//go:build windows

package windowsplatform

import "golang.org/x/sys/windows"

// Session zero hosts services, not selectable interactive desktop applications.
// This is a metadata lookup on an already discovered PID, not process scanning.
func InteractiveProcess(pid uint32) bool {
	var session uint32
	return windows.ProcessIdToSessionId(pid, &session) == nil && session != 0
}
