//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
)

func requireEndpointAdministrator() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("OWNER_PROXY_ADMIN_REQUIRED")
	}
	return nil
}
