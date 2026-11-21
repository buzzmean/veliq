//go:build windows

package main

import (
	"golang.org/x/sys/windows/svc"
	"testing"
)

func TestActivationWatchdogCustomRecoveryDoesNotRestartIntentionalStop(t *testing.T) {
	if policyStopExitCode(svc.Stop) != 0 || policyStopExitCode(svc.Shutdown) != 0 {
		t.Fatal("intentional stop became failure")
	}
	if policyStopExitCode(svc.Cmd(128)) != 1 {
		t.Fatal("watchdog request did not activate SCM recovery")
	}
}
