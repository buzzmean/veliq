package windowsplatform

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyRefreshQueueBoundedAndNeverClaimsBrowserUptake(t *testing.T) {
	var q policyRefreshQueue
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	q.request("owner", func(string) string {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return "USER_POLICY_REFRESH_REQUESTED"
	})
	<-entered
	for i := 0; i < 100; i++ {
		q.request("owner", func(string) string { t.Error("unbounded GP requests"); return "bad" })
	}
	if s := q.snapshot(); s.Requests != 1 || s.State != "USER_POLICY_REFRESH_PENDING" || s.LiveUptake != "NOT_OBSERVED" {
		t.Fatal(s)
	}
	close(release)
	end := time.Now().Add(time.Second)
	for q.snapshot().State == "USER_POLICY_REFRESH_PENDING" && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if s := q.snapshot(); s.State != "USER_POLICY_REFRESH_REQUESTED" || s.LiveUptake != "NOT_OBSERVED" || calls.Load() != 2 {
		t.Fatal(s)
	}
}
