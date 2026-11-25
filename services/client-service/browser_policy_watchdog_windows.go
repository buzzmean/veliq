//go:build windows

package clientservice

import (
	"context"
	"errors"
	"github.com/Microsoft/go-winio"
	windowsplatform "github.com/buzzmean/veliq/platform/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"net"
	"path/filepath"
	"strings"
	"time"
)

func dialPolicyWatchdog(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, `\\.\pipe\neexitlag-v1`)
}

// The custom control requests recovery, unlike an intentional Stop/Shutdown.
// SCM performs the restart using its existing bounded recovery actions.
func recoverPolicyWatchdog(m Manifest, path string, r *policyWatchdogRecovery) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsplatform.ServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	cfg, err := service.Config()
	if err != nil {
		return err
	}
	binary := filepath.Join(filepath.Dir(path), "veliq-service.exe")
	expected := `"` + binary + `" -config "` + path + `"`
	if !strings.EqualFold(cfg.BinaryPathName, expected) {
		return errors.New("WATCHDOG_SCM_PATH_MISMATCH")
	}
	state, err := service.Query()
	if err != nil {
		return err
	}
	now := time.Now()
	if !r.mayRecover(state.ProcessId, state.State == svc.Running, now) {
		return nil
	}

	if _, err = service.Control(svc.Cmd(128)); err != nil {
		return err
	}
	r.lastRequest = now
	return nil
}
