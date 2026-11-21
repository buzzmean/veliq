//go:build windows

package clientservice

import (
	"os/exec"
	"syscall"
)

// The verified Setup runs detached as SYSTEM in update mode: it replaces this
// service (stop/start) and the GUI files without any interactive owner checks.
func launchUpdateSetup(path string) error {
	cmd := exec.Command(path, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/NOCLOSEAPPLICATIONS", "/UPDATE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
