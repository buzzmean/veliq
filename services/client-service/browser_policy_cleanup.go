package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"os"
	"path/filepath"
)

// No activation/listener/recovery is started here. Ownership comes from the
// installation's bounded state journal, never from guessing that a PAC is local.
func (c *Controller) CleanupOwnedBrowserPolicies() error {
	if c.customPath == "" || c.BrowserOwnerSID == "" {
		return nil
	}
	c.activationMu.Lock()
	defer c.activationMu.Unlock()
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	return c.cleanupOwnedBrowserPoliciesLocked(nil)
}

// Caller serializes policy mutations with browser.mu.
func (c *Controller) cleanupOwnedBrowserPoliciesLocked(only *bool) error {
	c.browserPolicyInvalidateLocked(only)
	var failures []error
	for _, edge := range []bool{false, true} {
		if only != nil && edge != *only {
			continue
		}
		name := "browser-transport.json"
		owned := append([]string{}, c.browser.silent.Owned...)
		remove := c.browser.chromeRemove
		if edge {
			name = "edge-transport.json"
			e := c.edgeLocked()
			owned = append([]string{}, e.saved.Owned...)
			remove = e.remove
		}
		path := filepath.Join(filepath.Dir(c.customPath), name)
		if st, err := os.Lstat(path); err == nil {
			if !st.Mode().IsRegular() || st.Size() > 1024*1024 {
				failures = append(failures, errors.New("BROWSER_POLICY_JOURNAL_INVALID"))
				continue
			}
			raw, err := os.ReadFile(path)
			var saved struct {
				Owned  []string           `json:"owned_policy"`
				Silent browserSilentState `json:"silent_activation"`
			}
			if err != nil || json.Unmarshal(raw, &saved) != nil {
				failures = append(failures, errors.New("BROWSER_POLICY_JOURNAL_INVALID"))
				continue
			}
			if edge {
				owned = append(owned, saved.Owned...)
			} else {
				owned = append(owned, saved.Silent.Owned...)
			}
		} else if !os.IsNotExist(err) {
			failures = append(failures, errors.New("BROWSER_POLICY_JOURNAL_UNAVAILABLE"))
			continue
		}
		if len(owned) == 0 {
			continue
		}
		if remove == nil {
			if edge {
				remove = wp.EdgeProxyPolicyRemove
			} else {
				remove = wp.ChromeProxyPolicyRemove
			}
		}
		if err := remove(c.BrowserOwnerSID, owned); err != nil {
			failures = append(failures, err)
		}
	}
	c.activation.mu.Lock()
	defer c.activation.mu.Unlock()
	c.activation.policyCleanup = "REMOVED_OR_ABSENT"
	if len(failures) > 0 {
		c.activation.policyCleanup = "CLEANUP_FAILED_OR_FOREIGN_POLICY_PRESERVED"
	}
	return errors.Join(failures...)
}

// Host cancellation represents an intentional stop/shutdown. Initialization
// errors and process crashes do not authorize removal of the fail-closed guard.
func (c *Controller) CloseForHost(parent context.Context) error {
	if c.emergencyClosed.Load() {c.Close();return nil}
	var cleanup error
	if parent.Err() != nil {
		c.activationMu.Lock()
		c.activation.stopAutomatic.Store(true)
		c.mu.Lock()
		c.enabled = false
		c.mu.Unlock()
		// Cached PAC gets DIRECT at the deliberate stop boundary, before removal.
		guardErr := c.publishBrowserGuard(false)
		authorityErr := c.releaseBrowserAuthority()
		c.browser.mu.Lock()
		cleanup = errors.Join(guardErr, authorityErr, c.cleanupOwnedBrowserPoliciesLocked(nil))
		c.browser.mu.Unlock()
		c.activationMu.Unlock()
	}
	c.Close()
	return cleanup
}

// Only a credential-less ActivationOnly installation may discard stale policy
// before enrollment. An activated boot waiting for CP must retain its guard.
func (c *Controller) CleanupPreactivationBrowserPolicies() error {
	c.activation.mu.Lock()
	allowed := c.activation.preactivationCleanup
	c.activation.mu.Unlock()
	if !allowed {
		return nil
	}
	return c.CleanupOwnedBrowserPolicies()
}

// Mutation IPC already holds activationMu; never recursively take it.
func (c *Controller) cleanupBrowserPoliciesForMutation() error {
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	return c.cleanupOwnedBrowserPoliciesLocked(nil)
}
