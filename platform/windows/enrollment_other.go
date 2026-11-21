//go:build !windows

package windowsplatform

import (
	"context"
	"github.com/buzzmean/neexitlag/core/enrollment"
)

func EnrollmentHardware(context.Context) (enrollment.Hardware, error) {
	return enrollment.Hardware{}, ErrUnavailable
}
func ProtectActivationFile(string) error { return nil } // portable tests use file mode 0600
