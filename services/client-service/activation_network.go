package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/enrollment"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

// New/unconfigured controllers and valid legacy installations retain their
// established behavior. Code-managed boot must validate binding/authentication
// before any WinDivert handle or browser policy is activated.
// An ended subscription blocks the same way until the next successful payment.
func (c *Controller) activationNetworkAllowed() bool {
	return !c.activation.networkBlocked.Load() && !c.subscription.suspended.Load()
}
func (c *Controller) activationHardware(ctx context.Context, salt []byte) (string, error) {
	c.activation.mu.Lock()
	hardware := c.activation.hardware
	c.activation.mu.Unlock()
	if hardware == nil {
		hardware = wp.EnrollmentHardware
	}
	h, err := hardware(ctx)
	hash, report, hashErr := enrollment.HardwareHashDiagnostics(h, salt)
	if err != nil {
		hash = ""
		report = enrollment.HardwareDiagnostics{UUID: "NOT_QUERIED", BoardSerial: "NOT_QUERIED", MAC: "NOT_QUERIED", Reason: "HARDWARE_METADATA_QUERY_FAILED"}
		hashErr = errors.New("HARDWARE_ID_UNAVAILABLE")
	}
	c.activation.mu.Lock()
	c.activation.diagnostics = report
	c.activation.mu.Unlock()
	return hash, hashErr
}
func activationNetworkMutation(method string) bool {
	switch method {
	case "browser.native.enable", "browser.prepare", "browser.start", "browser.confirm", "browser.silent.apply", "browser.silent.guard", "edge.prepare", "edge.confirm", "edge.policy", "edge.silent.apply":
		return true
	}
	return false
}

// Starting workers is not readiness. A transient capture failure must remain
// pending, with a bounded retry, without asking the user to reactivate/restart.
func (c *Controller) startActivatedCapture(connected bool, started *bool) error {
	c.mu.Lock()
	automatic := c.settings.Automatic
	c.mu.Unlock()
	if *started || !automatic || !connected || c.activation.stopAutomatic.Load() || c.ctx.Err() != nil {
		return nil
	}
	_, err := c.Handle(c.ctx, "optimize", []byte(`{"enabled":true}`))
	if err == nil {
		*started = true
	}
	return err
}
