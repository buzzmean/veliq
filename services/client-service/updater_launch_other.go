//go:build !windows

package clientservice

import "errors"

func launchUpdateSetup(string) error { return errors.New("UPDATE_UNSUPPORTED_PLATFORM") }
