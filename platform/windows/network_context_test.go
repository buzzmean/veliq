package windowsplatform

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDescribeRunFailureReportsTimeoutAndBoundedStderr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	long := "Get-NetRoute: \x1b[31mfailed\x1b[0m\r\n" + strings.Repeat("x", 500)
	got := describeRunFailure(ctx, errors.New("exit status 1"), 8*time.Second, long)
	for _, want := range []string{"exit status 1", "8s", "query budget exceeded", "Get-NetRoute"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
	if strings.ContainsAny(got, "\x1b\r\n") || len(got) > 450 {
		t.Fatalf("unsanitized or unbounded: %q", got)
	}
	plain := describeRunFailure(context.Background(), errors.New("exit status 1"), time.Second, "")
	if strings.Contains(plain, "budget") || strings.Contains(plain, "stderr") {
		t.Fatalf("false timeout/stderr claim: %q", plain)
	}
}
