package main

import (
	"context"
	"time"
)

func recoveryHostStopped(state string) bool {
	return state == "STOP_PENDING" || state == "STOPPED" || state == "NOT_INSTALLED"
}

// A recovery child is not another SCM host and must not survive a deliberate
// SCM stop. Unknown/starting is not proof of a stop; avoid read/permission races.
func watchRecoveryHost(ctx context.Context, cancel context.CancelFunc, state func() string, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if recoveryHostStopped(state()) {
			cancel()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
