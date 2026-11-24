//go:build !windows

package windowsplatform

import (
	"github.com/buzzmean/neexitlag/core/clubhealth"
	"time"
)

func DiagnosticWindowsEvents(time.Time) ([]clubhealth.Diagnostic, error) { return nil, ErrUnavailable }
