//go:build !windows

package windowsplatform

func AllowOwnerReadFile(string, string) error { return nil }
