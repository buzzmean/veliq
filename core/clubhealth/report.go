// Package clubhealth defines the bounded, device-authenticated club health feed.
package clubhealth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"time"

	"github.com/buzzmean/veliq/core/security"
)

const (
	Endpoint     = "/api/v1/club/health"
	MaxEvents    = 16
	Retention    = 14 * 24 * time.Hour
	Heartbeat    = 30 * time.Second
	MissingAfter = 2 * time.Minute
)

var (
	eventID  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	appName  = regexp.MustCompile(`^[a-z0-9][a-z0-9 ._()+-]{0,74}\.exe$`)
	buildID  = regexp.MustCompile(`^[0-9a-zA-Z.-]{1,48}(\+modified)?$`)
	reasonID = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,47}$`)
)

type Event struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Code   uint32    `json:"code,omitempty"`
	App    string    `json:"app,omitempty"`
	Route  string    `json:"route,omitempty"`
	Reason string    `json:"reason,omitempty"`
}

type Report struct {
	Build   string  `json:"build,omitempty"`
	Capture string  `json:"capture,omitempty"`
	LAN     string  `json:"lan,omitempty"`
	Events  []Event `json:"events,omitempty"`
}

type Request struct {
	Report Report         `json:"report"`
	Proof  security.Proof `json:"proof"`
}

type Config struct {
	LANTarget string `json:"lan_target,omitempty"`
}

func (r Report) Discovery() bool {
	return r.Build == "" && r.Capture == "" && r.LAN == "" && len(r.Events) == 0
}

func (r Report) Audience() (string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "club-health-v1:" + hex.EncodeToString(sum[:]), nil
}

func ValidApp(name string) bool      { return appName.MatchString(name) }
func ValidReason(reason string) bool { return reasonID.MatchString(reason) }

func ValidRoute(route string) bool {
	switch route {
	case "", "DIRECT", "DIRECT+", "LOCAL", "RELAY", "RELAY_REQUIRED", "BLOCK":
		return true
	}
	return false
}

func (e Event) Valid(now time.Time) bool {
	if !eventID.MatchString(e.ID) || e.At.Before(now.Add(-Retention)) || e.At.After(now.Add(time.Minute)) ||
		e.App != "" && !ValidApp(e.App) || !ValidRoute(e.Route) || e.Reason != "" && !ValidReason(e.Reason) {
		return false
	}
	switch e.Kind {
	case "application_report", "application_crash", "capture_start_failed", "capture_failed", "route_failure", "capture_history_gap",
		"veliq_crash", "veliq_start_failed", "langame_crash", "langame_start_failed", "langame_error",
		"unexpected_restart", "shutdown_requested", "bugcheck", "storage_error", "network_error",
		"lan_unreachable", "lan_recovered", "report_delivery_gap", "event_log_unavailable", "events_overflow":
		return true
	}
	return false
}

func (r Report) Validate(now time.Time) error {
	if r.Discovery() {
		return nil
	}
	if !buildID.MatchString(r.Build) || len(r.Events) > MaxEvents {
		return errors.New("invalid health build or event count")
	}
	switch r.Capture {
	case "ready", "off", "error", "starting":
	default:
		return errors.New("invalid capture state")
	}
	switch r.LAN {
	case "", "pending", "reachable", "unreachable":
	default:
		return errors.New("invalid LAN state")
	}
	for _, event := range r.Events {
		if !event.Valid(now) {
			return errors.New("invalid health event")
		}
	}
	return nil
}

// A LAN probe can only open one configured private TCP service. It never
// accepts a URL, hostname, local listener, IPv6 zone, or a public address.
func ValidLANTarget(target string) bool {
	if target == "" {
		return true
	}
	addr, err := netip.ParseAddrPort(target)
	return err == nil && addr.Port() != 0 && addr.Addr().Zone() == "" &&
		addr.Addr().IsPrivate() && !addr.Addr().Is4In6()
}
