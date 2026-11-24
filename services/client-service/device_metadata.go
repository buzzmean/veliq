package clientservice

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/deviceinfo"
)

type deviceMetadataSource interface {
	SupportsDeviceMetadata(context.Context) (bool, error)
	DeviceMetadata(context.Context, deviceinfo.Details) error
}

func (c *Controller) runDeviceMetadata(ctx context.Context, cp deviceMetadataSource) {
	name, err := os.Hostname()
	if err != nil {
		return
	}
	version := "0.3." + BuildSequence
	if BuildSequence == "0" {
		version = "0.3.0-dev"
	}
	details := deviceinfo.Details{ComputerName: name, Version: version}
	if !details.Valid() {
		return
	}
	supported := false
	for {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if !supported {
			supported, err = cp.SupportsDeviceMetadata(requestCtx)
		}
		if supported {
			err = cp.DeviceMetadata(requestCtx, details)
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		delay := time.Minute
		if !supported || errors.Is(err, controlclient.ErrNotSupported) {
			supported = false
			delay = 15 * time.Minute
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		// Имя Windows может измениться во время работы службы.
		if next, e := os.Hostname(); e == nil {
			updated := deviceinfo.Details{ComputerName: next, Version: version}
			if updated.Valid() {
				details = updated
			}
		}
	}
}
