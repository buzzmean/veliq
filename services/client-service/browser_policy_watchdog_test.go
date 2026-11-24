package clientservice

import (
	wp "github.com/buzzmean/veliq/platform/windows"
	"testing"
	"time"
)

func TestActivationPolicyWatchdogCrashHangStopAndRecoveryMasks(t *testing.T) {
	now := time.Now()
	ready := Snapshot{Connected: true, Optimizing: true, CapturePermitted: true, Backend: wp.CaptureStatus{Ready: true}, BrowserPolicy: BrowserPolicyHealth{ChromeReady: true, EdgeReady: true, LastCheck: now, ChromeCheckedAt: now, EdgeCheckedAt: now}}
	for _, kind := range []string{"kill", "hang", "relay-loss", "optimization-off", "capture-loss", "freeze-stale-state", "pending-activation"} {
		t.Run(kind, func(t *testing.T) {
			state := ready
			ptr := &state
			switch kind {
			case "kill", "hang":
				ptr = nil
			case "relay-loss":
				state.Connected = false
			case "optimization-off":
				state.Optimizing = false
			case "capture-loss":
				state.Backend.Ready = false
			case "freeze-stale-state":
				state.BrowserPolicy.LastCheck = now.Add(-time.Minute)
			case "pending-activation":
				state.CapturePermitted = false
			}
			if got := browserPolicyCleanupMask(ptr, now); got != [2]bool{true, true} {
				t.Fatal("dead policy survives", got)
			}
		})
	}
	if got := browserPolicyCleanupMask(&ready, now); got != [2]bool{} {
		t.Fatal("healthy state removed")
	}
	ready.BrowserPolicy.EdgeReady = false
	if got := browserPolicyCleanupMask(&ready, now); got != [2]bool{false, true} {
		t.Fatal("unrelated browser disrupted")
	}
}
func TestActivationWatchdogRecoveryRespectsIntentionalStopAndStartupGrace(t *testing.T) {
	now := time.Now()
	r := policyWatchdogRecovery{}
	if r.mayRecover(123, true, now) {
		t.Fatal("fresh service restarted")
	}
	for i := 0; i < 3; i++ {
		r.observe(nil, now)
	}
	if r.mayRecover(123, true, now.Add(time.Second)) {
		t.Fatal("startup grace bypassed")
	}
	r.observe(&Snapshot{ServicePID: 123}, now)
	for i := 0; i < 2; i++ {
		r.observe(nil, now)
	}
	if r.mayRecover(123, true, now) {
		t.Fatal("one read race triggered recovery")
	}
	r.observe(nil, now)
	if !r.mayRecover(123, true, now) {
		t.Fatal("durable IPC loss did not recover")
	}
	r.lastRequest = now
	if r.mayRecover(123, true, now.Add(time.Second)) {
		t.Fatal("restart storm")
	}
	if r.mayRecover(123, false, now.Add(time.Minute)) {
		t.Fatal("intentional Stop triggered restart")
	}
	if r.mayRecover(124, true, now.Add(time.Minute)) {
		t.Fatal("new PID bypassed startup grace")
	}
}
