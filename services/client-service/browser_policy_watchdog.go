package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/ipc"
	"github.com/buzzmean/veliq/core/security"
)

// Independent scheduled SYSTEM process: local IPC and exact journal-owned
// registry cleanup only. No backend, enrollment, route changes or Internet I/O.
func RunBrowserPolicyWatchdog(ctx context.Context, manifestPath string) error {
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return errors.New("WATCHDOG_CONFIG_INVALID")
	}
	c := New(ctx)
	defer c.Close()
	c.BrowserOwnerSID = m.OwnerSID
	c.customPath = filepath.Join(m.StateDirectory, "profiles.json")
	recovery := policyWatchdogRecovery{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var status *Snapshot
		attempt, cancel := context.WithTimeout(ctx, time.Second)
		if s, err := readPolicyWatchdogStatus(attempt, m); err == nil {
			status = &s
		}
		cancel()

		recovery.observe(status, time.Now())
		mask := browserPolicyCleanupMask(status, time.Now())
		for i, clear := range mask {
			if clear {
				edge := i == 1
				c.activationMu.Lock()
				c.browser.mu.Lock()
				_ = c.cleanupOwnedBrowserPoliciesLocked(&edge)
				c.browser.mu.Unlock()
				c.activationMu.Unlock()
			}
		}

		if status == nil && recovery.failures >= 3 {
			_ = recoverPolicyWatchdog(m, manifestPath, &recovery)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func readPolicyWatchdogStatus(ctx context.Context, m Manifest) (Snapshot, error) {
	var out Snapshot
	token, err := os.ReadFile(m.TokenFile)
	if err != nil {
		return out, err
	}
	conn, err := dialPolicyWatchdog(ctx)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	id, err := security.NewID()
	if err != nil {
		return out, err
	}
	if err = ipc.Write(conn, ipc.Request{Version: ipc.Version, ID: id, SentAt: time.Now(), Token: strings.TrimSpace(string(token)), Method: "status"}); err != nil {
		return out, err
	}
	var response struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		OK      bool            `json:"ok"`
		Data    json.RawMessage `json:"data"`
		Code    string          `json:"code"`
		Error   string          `json:"error"`
	}
	if err = ipc.Read(conn, &response); err != nil {
		return out, err
	}
	if !response.OK || response.Version != ipc.Version || response.ID != id {
		return out, errors.New("WATCHDOG_IPC_UNAVAILABLE")
	}
	if err = json.Unmarshal(response.Data, &out); err != nil {
		return out, err
	}
	return out, nil
}

func browserPolicyCleanupMask(s *Snapshot, now time.Time) [2]bool {
	if s == nil || !s.Connected || !s.Optimizing || !s.Backend.Ready || !s.CapturePermitted || s.BrowserPolicy.LastCheck.IsZero() || now.Sub(s.BrowserPolicy.LastCheck) > 15*time.Second {
		return [2]bool{true, true}
	}
	return [2]bool{!s.BrowserPolicy.ChromeReady || s.BrowserPolicy.ChromeCheckedAt.IsZero() || now.Sub(s.BrowserPolicy.ChromeCheckedAt) > 15*time.Second, !s.BrowserPolicy.EdgeReady || s.BrowserPolicy.EdgeCheckedAt.IsZero() || now.Sub(s.BrowserPolicy.EdgeCheckedAt) > 15*time.Second}
}

type policyWatchdogRecovery struct {
	failures    int
	seenRunning time.Time
	lastRequest time.Time
	pid         uint32
	observed    bool
}

func (r *policyWatchdogRecovery) observe(s *Snapshot, now time.Time) {
	if s != nil {
		if s.ServicePID != 0 && s.ServicePID != r.pid {
			r.pid = s.ServicePID
			r.seenRunning = now
		}
		r.failures = 0
		r.observed = true
	} else {
		r.failures++
	}
}

func (r *policyWatchdogRecovery) mayRecover(pid uint32, running bool, now time.Time) bool {
	if !running {
		r.pid = 0
		r.seenRunning = time.Time{}
		r.observed = false
		return false
	}
	if pid == 0 {
		return false
	}
	if pid != r.pid {
		r.pid = pid
		r.seenRunning = now
		r.observed = false
		return false
	}
	return r.failures >= 3 && (r.observed || now.Sub(r.seenRunning) >= 30*time.Second) && (r.lastRequest.IsZero() || now.Sub(r.lastRequest) >= time.Minute)
}
