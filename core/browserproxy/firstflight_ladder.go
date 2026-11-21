package browserproxy

import (
	"context"
	"net"
	"time"
)

// WatchFirstFlight is a bounded single step of a finite route ladder. It may
// resend ONLY a complete TLS ClientHello (+dummy CCS), before ANY origin byte.
// Callers bound the number of steps. TLS early data/application records, partial
// hellos and an established TLS session are never replayed or migrated.
func WatchFirstFlight(ctx context.Context, conn net.Conn, timeout time.Duration, next func(context.Context) (net.Conn, error), failed func(string)) net.Conn {
	return WatchRelayOrigin(conn, OriginConfig{Context: ctx, Health: NewOriginHealth(), Silence: timeout, OnFailure: failed, NextFlow: func(ctx context.Context, reason string) (net.Conn, error) { return next(ctx) }})
}

// PlanReporter exposes a changing first-flight decision without suggesting an
// established TLS session was migrated. Each step is still a new upstream TCP.
type PlanReporter interface{ CurrentPlan() Plan }
