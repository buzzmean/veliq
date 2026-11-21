//go:build !windows

package browserproxy

import "os"

func openRecoveryGuard(path string) (*os.File, error) { return os.Open(path) }
