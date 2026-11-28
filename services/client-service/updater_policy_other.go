//go:build !windows

package clientservice

func readManagedUpdatePolicy() (bool, error) { return false, nil }
