package clientservice

import (
	"github.com/buzzmean/neexitlag/core/measurement"
	"github.com/buzzmean/neexitlag/core/telemetry"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
	"time"
)

type DropDiagnostics struct {
	Capture              map[string]telemetry.Metric            `json:"capture"`
	Transport            map[string]map[string]telemetry.Metric `json:"transport"`
	RemoteRelayAvailable bool                                   `json:"remote_relay_available"`
	ProbeLossScope       string                                 `json:"probe_loss_scope"`
	// ProbeAccounting separates lost probes from late ones, per route.
	ProbeAccounting []measurement.AccountView `json:"probe_accounting"`
}

func (c *Controller) DropDiagnostics() DropDiagnostics {
	result := DropDiagnostics{Transport: map[string]map[string]telemetry.Metric{}, ProbeLossScope: "unanswered sent probes; hop attribution unknown"}
	if backend, ok := c.Backend.(interface {
		Diagnostics(uint32) windowsplatform.CaptureEvidence
	}); ok {
		result.Capture = backend.Diagnostics(0).LocalDrops
	}
	c.mu.Lock()
	sources := make(map[string]func() map[string]telemetry.Metric, len(c.transportDrops))
	for id, source := range c.transportDrops {
		sources[id] = source
	}
	c.mu.Unlock()
	for id, source := range sources {
		result.Transport[id] = source()
	}
	result.ProbeAccounting = c.Measurements.Accounts(time.Now())
	return result
}
