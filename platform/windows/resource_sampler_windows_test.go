//go:build windows

package windowsplatform

import (
	"os"
	"testing"

	"github.com/buzzmean/veliq/core/flightrecorder"
)

func TestNativeResourceSamplerQueryOnlyHandlesAndStableIdentity(t *testing.T) {
	s := NewResourceSampler(uint32(os.Getpid()))
	s.interval = 0
	first := s.Observe()
	required := flightrecorder.ResourceCPU | flightrecorder.ResourceIO | flightrecorder.ResourceWorkingSet | flightrecorder.ResourcePrivate | flightrecorder.ResourceHandles
	if first.Sample.Known&required != required {
		t.Fatal("own-process native counters unavailable", first.Sample.Known, first.Sample.ErrorCode, first.Sample.NativeCode)
	}
	for range 64 {
		next := s.Observe()
		if next.Sample.Birth != first.Sample.Birth || next.Sample.PID != first.Sample.PID || next.Sample.Known&required != required {
			t.Fatal("native observation identity/capability changed", next.Sample.ErrorCode)
		}
		if next.Sample.Handles > first.Sample.Handles+4 {
			t.Fatal("query-only sampling leaked handles", first.Sample.Handles, next.Sample.Handles)
		}
	}
	if first.Sample.Known&flightrecorder.ResourceThreads != 0 {
		t.Fatal("native thread count claimed without bounded source")
	}
}
func TestNativeResourceSamplerAbsentPIDDoesNotClaimObservedExit(t *testing.T) {
	out := NewResourceSampler(^uint32(0)).Observe()
	if out.Sample.Known != 0 || out.Sample.ErrorCode == "OK" || out.Sample.ErrorCode == "PROCESS_EXITED" {
		t.Fatal("failed query presented as observed process exit", out)
	}
}
