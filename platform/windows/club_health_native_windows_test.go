//go:build windows

package windowsplatform

import (
	"testing"
	"time"
)

func TestPersistentNativeEventQuery(t *testing.T) {
	_, err := DiagnosticWindowsEvents(time.Now())
	if err != nil {
		t.Fatal("native Windows event query:", err)
	}
}
