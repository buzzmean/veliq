//go:build !windows

package windowsplatform

import (
	"context"
	"github.com/buzzmean/neexitlag/core/routing"
)

type WinDivertBackend struct{}

func NewWinDivert(DriverFiles, *routing.Engine) *WinDivertBackend { return &WinDivertBackend{} }
func (*WinDivertBackend) Start(context.Context, Classifier) error { return ErrUnavailable }
func (*WinDivertBackend) Stop() error                             { return nil }
func (*WinDivertBackend) Status() CaptureStatus {
	return CaptureStatus{Backend: "WinDivert", Error: "Windows runtime is required; all traffic remains DIRECT"}
}

func (*WinDivertBackend) Traffic() (uint64, uint64) { return 0, 0 }
