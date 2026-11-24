//go:build !windows

package main

import "errors"

func requireEndpointAdministrator() error { return errors.New("OWNER_PROXY_WINDOWS_REQUIRED") }
