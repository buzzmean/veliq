package clientservice

import (
	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/flightrecorder"
	"runtime"
)

// This deliberately avoids Snapshot, activationStatus (certificate I/O), process
// enumeration and transport history. Busy locks mean unknown, never healthy.
func (c *Controller) flightStateSnapshot() flightrecorder.RuntimeState {
	var out flightrecorder.RuntimeState
	if c.mu.TryLock() {
		out.CaptureEnabled, out.Automatic = c.enabled, c.settings.Automatic
		out.Known |= flightrecorder.StateCapture | flightrecorder.StateAutomatic
		c.mu.Unlock()
	}
	if c.activation.mu.TryLock() {
		out.ActivationState = c.activation.status.State
		out.Known |= flightrecorder.StateActivation
		c.activation.mu.Unlock()
	}
	// The native backend exposes two atomic cumulative byte counters. Avoid its
	// rich ingress snapshot, process enumeration and per-flow records here.
	if runtime.GOOS == "windows" {
		if backend, ok := c.Backend.(interface{ Traffic() (uint64, uint64) }); ok {
			out.CaptureRXBytes, out.CaptureTXBytes = backend.Traffic()
			out.CaptureTrafficKnown = true
		}
	}
	out.IPCInFlight = c.flightIPCInFlight.Load()
	out.Known |= flightrecorder.StateIPC
	return out
}

// Only fixed dispatcher labels cross the journal boundary. In particular an
// unknown method, request body, activation code or path is never recorded.
func flightOperation(method string) string {
	switch method {
	case "activation.set":
		return "ACTIVATION_SET"
	case "optimize":
		return "OPTIMIZE"
	case "settings.set":
		return "SETTINGS_SET"
	case "profile.set":
		return "PROFILE_SET"
	case "profile.delete":
		return "PROFILE_DELETE"
	case "auto.commit":
		return "AUTO_COMMIT"
	case "browser.native.enable":
		return "NATIVE_BROWSER_ENABLE"
	case "browser.native.disable":
		return "NATIVE_BROWSER_DISABLE"
	case "browser.start":
		return "BROWSER_START"
	case "browser.prepare":
		return "BROWSER_PREPARE"
	case "browser.confirm":
		return "BROWSER_CONFIRM"
	default:
		return ""
	}
}

func (c *Controller) beginFlightOperation(method string) func(error) {
	op := flightOperation(method)
	d := c.diagnostics.Load()
	if op == "" || d == nil {
		return nil
	}
	e := d.event("CONTROL", "CONTROL_OPERATION", "observed", "REQUEST_BEGIN")
	e.Operation, e.Incident = op, e.ID
	d.offer(e, "")
	return func(err error) {
		next := d.event("CONTROL", "CONTROL_OPERATION", "observed", "REQUEST_RETURNED")
		next.Operation, next.Incident = op, e.ID
		if err != nil {
			next.Code, next.NativeCode = clubhealth.ErrorCode(err)
		}
		d.offer(next, "")
	}
}

func (c *Controller) activationFlightPhase(operation string) {
	if d := c.diagnostics.Load(); d != nil {
		e := d.event("ACTIVATION", "ACTIVATION_PHASE", "observed", "PHASE_ENTERED")
		e.Operation = operation // Internal call sites below use fixed literals only.
		d.offer(e, "activation-phase")
	}
}

func (c *Controller) activationFlightResult(err error) {
	d := c.diagnostics.Load()
	if d == nil {
		return
	}
	e := d.event("ACTIVATION", "ACTIVATION_PHASE", "observed", "ATTEMPT_RETURNED")
	e.Operation = "ACTIVATION_ATTEMPT"
	if err != nil {
		e.State = "failed"
		e.Code, e.NativeCode = clubhealth.ErrorCode(err)
		// Reuse the existing fixed activation-code allowlist, never the error body.
		if safe := activationSafeError(err); safe != "ACTIVATION_UNAVAILABLE" {
			e.Code = safe
		}
		switch err.Error() {
		case "ACTIVATION_UNAVAILABLE", "ACTIVATION_CHANGED", "ACTIVATION_KEY_FAILED", "ACTIVATION_INVALID_RESPONSE":
			e.Code = err.Error()
		}
	}
	d.offer(e, "activation-attempt")
}
