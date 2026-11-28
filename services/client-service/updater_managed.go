package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Called under u.op only, after the signed Latest package has been verified.
// No LANGAME session inspection is needed: a short VELIQ outage is permitted.
func (u *updater) installManagedLocked() error {
	managed, reason := u.updateMode()
	if !managed || reason != "" {
		if reason == "" {
			reason = "UPDATE_POLICY_WITHDRAWN"
		}
		u.set("DISABLED", reason, nil)
		return errors.New(reason)
	}
	if u.readyPath == "" || u.ready.Build <= u.current || u.snapshot().State != "READY" {
		return errors.New("UPDATE_NOT_READY")
	}
	// O_EXCL is shared across updater instances and survives service restart.
	// One automatic attempt per build; a failed launch/rollback must not loop.
	path := filepath.Join(u.dir, "updates", fmt.Sprintf("auto-install-%d.attempt", u.ready.Build))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		code := "UPDATE_AUTO_ATTEMPT_UNAVAILABLE"
		if errors.Is(err, os.ErrExist) {
			code = "UPDATE_AUTO_ATTEMPT_RECORDED"
		}
		u.set("INSTALL_FAILED", code, &u.ready)
		return errors.New(code)
	}
	err = json.NewEncoder(f).Encode(struct {
		Build  uint64    `json:"build"`
		SHA256 string    `json:"sha256"`
		At     time.Time `json:"attempted_at"`
	}{u.ready.Build, u.ready.SetupSHA256, time.Now().UTC()})
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		u.set("INSTALL_FAILED", "UPDATE_AUTO_ATTEMPT_UNAVAILABLE", &u.ready)
		return errors.New("UPDATE_AUTO_ATTEMPT_UNAVAILABLE")
	}
	// Re-read authorization after downloading and recording the attempt, so
	// disabling the machine policy never depends on a service restart.
	if managed, reason = u.updateMode(); !managed || reason != "" {
		u.set("DISABLED", "UPDATE_POLICY_WITHDRAWN", nil)
		return errors.New("UPDATE_POLICY_WITHDRAWN")
	}
	return u.launchReadyLocked(true)
}

// Background downloads are capped at 2 MiB/s with a 64 KiB initial burst. The
// wait is cancellable and applies to direct and relay downloads alike.
const managedUpdateBytesPerSecond = 2 << 20
const managedUpdateBurst = 64 << 10

type pacedUpdateReader struct {
	ctx     context.Context
	reader  io.Reader
	started time.Time
	bytes   int64
}

func (r *pacedUpdateReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	if charged := r.bytes + int64(len(p)) - managedUpdateBurst; charged > 0 {
		due := r.started.Add(time.Duration(charged) * time.Second / managedUpdateBytesPerSecond)
		if wait := time.Until(due); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			case <-timer.C:
			}
		}
	}
	n, err := r.reader.Read(p)
	r.bytes += int64(n)
	return n, err
}
