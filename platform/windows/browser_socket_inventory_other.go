//go:build !windows

package windowsplatform

func BrowserTCPSockets() ([]BrowserTCPSocket, bool, error) { return nil, false, ErrUnavailable }
