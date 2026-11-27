//go:build !windows && !linux

package windowsplatform

import "github.com/buzzmean/veliq/core/flightrecorder"

func readNativeResources(pid uint32) flightrecorder.ResourceSample {
	return flightrecorder.ResourceSample{PID: pid, Source: "UNAVAILABLE", ErrorCode: "RESOURCE_UNSUPPORTED"}
}
