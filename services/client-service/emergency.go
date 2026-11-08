package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"github.com/buzzmean/neexitlag/core/emergency"
)

// ConfigureEmergencyManager is called before opening the authenticated pipe.
func (c *Controller) ConfigureEmergencyManager(manager *emergency.Manager) {
	handler := manager.Wrap(nil)
	c.emergencyHandler = func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
		if !c.emergencyClubAllowed() {
			return nil, errors.New("EMERGENCY_CLUB_ONLY")
		}
		return handler(ctx, method, raw)
	}
}

// Only the protected club configuration grants this capability. Neither an
// owner IPC payload nor a UI flag can turn a personal installation into a club.
// A known player account also denies it if stale club settings remain.
func (c *Controller) emergencyClubAllowed() bool {
	if !c.clubMode.Load() {
		return false
	}
	c.activation.mu.Lock()
	m, configured := c.activation.manifest, c.activation.configured
	c.activation.mu.Unlock()
	if !configured {
		return true // configured club can recover before enrollment/CP startup
	}
	record, err := readActivation(m)
	if err != nil {
		return os.IsNotExist(err)
	}
	return record.Account.Kind != "player"
}
func(c *Controller) EmergencyStopping()bool{return c.emergencyStopped.Load()}
func emergencyMethod(method string)bool{return method=="emergency.status"||method=="emergency.stop"||method=="emergency.finish"}

// BeginEmergencyStop is called only after the service verifies the independent
// offline password. Block background activation/retries before waiting for slow
// initialization. Keep cached PAC listeners alive until owned settings are restored.
// The latch is never cleared in this service process.
func (c *Controller) BeginEmergencyStop() {
	c.emergencyStopped.Store(true)
	c.activation.stopAutomatic.Store(true)
}

// FinishEmergencyStop must run after the startup goroutine has returned.
// Keep all cleanup failures visible and preserve settings not owned by VELIQ.
func (c *Controller) FinishEmergencyStop() error {
	c.activationMu.Lock()
	c.mu.Lock()
	c.enabled=false
	c.mu.Unlock()
	c.Measurements.Active.Store(false)
	guardErr:=c.publishBrowserGuard(false)
	authorityErr:=c.releaseBrowserAuthority()
	c.browser.mu.Lock()
	policyErr:=c.cleanupOwnedBrowserPoliciesLocked(nil)
	c.browser.mu.Unlock()
	var captureErr error
	if c.Backend!=nil {captureErr=c.Backend.Stop()}
	c.activationMu.Unlock()
	c.Close()
	if c.Backend!=nil && c.Backend.Status().Ready {captureErr=errors.New("EMERGENCY_CAPTURE_STILL_ACTIVE")}
	if errors.Join(guardErr,authorityErr,policyErr,captureErr)!=nil {return errors.New("EMERGENCY_CLEANUP_FAILED")}
	c.emergencyClosed.Store(true)
	return nil
}
