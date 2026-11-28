//go:build !windows

package clientservice

import "errors"

func launchUpdateSetup(string) error { return errors.New("UPDATE_UNSUPPORTED_PLATFORM") }

func launchUpdateSetupObserved(path string, exited func()) error { return launchUpdateSetup(path) }

func launchManagedUpdateSetupObserved(path string, exited func()) error {
	return launchUpdateSetup(path)
}
