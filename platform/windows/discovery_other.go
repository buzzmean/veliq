//go:build !windows

package windowsplatform

import (
	"errors"
)

type unavailableDiscovery struct{}

func NewDiscovery() Discovery { return unavailableDiscovery{} }
func (unavailableDiscovery) Lookup(uint32) (ProcessIdentity, error) {
	return ProcessIdentity{}, ErrUnavailable
}
func (unavailableDiscovery) List() ([]ProcessIdentity, error) {
	return nil, errors.New("process discovery requires Windows")
}

func IsCurrent(ProcessIdentity) bool { return false }
