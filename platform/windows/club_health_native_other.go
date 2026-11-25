//go:build !windows

package windowsplatform

import (
	"github.com/buzzmean/veliq/core/clubhealth"
	"time"
)

func DiagnosticWindowsEvents(time.Time) ([]clubhealth.Diagnostic, error) { return nil, ErrUnavailable }
func DiagnosticLanGameState() clubhealth.Diagnostic {
	return clubhealth.Diagnostic{Component: "LANGAME", Observer: "SCM_QUERY", State: "unknown", Code: "SCM_UNAVAILABLE"}
}
