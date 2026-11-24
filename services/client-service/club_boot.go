package clientservice

import (
	"os"
	"path/filepath"
	"time"

	"github.com/buzzmean/veliq/core/security"
)

func clubBootReady(m Manifest) bool {
	path := filepath.Join(filepath.Dir(m.DeviceIdentityFile), "club-boot-ready.json")
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1024 {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var marker struct {
		Version int    `json:"version"`
		Source  string `json:"source"`
		Created string `json:"created_at"`
	}
	return security.Parse(raw, &marker) == nil && marker.Version == 1 && marker.Source == "VELIQ_CLUB_BOOT"
}
func (c *Controller) waitClubBoot(m Manifest) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-tick.C:
		}
		if !clubBootReady(m) {
			continue
		}
		c.activation.mu.Lock()
		c.activation.paused = false
		c.activation.status.State = "ACTIVATING"
		wake := c.activation.wake
		c.activation.mu.Unlock()
		select {
		case wake <- struct{}{}:
		default:
		}
		return
	}
}
