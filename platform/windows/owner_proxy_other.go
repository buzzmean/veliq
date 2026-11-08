//go:build !windows

package windowsplatform

import "errors"

func OwnerBrowserProxyPolicyAvailable(string, bool, []string) error {
	return errors.New("OWNER_PROXY_WINDOWS_REQUIRED")
}

func ReadOwnerSystemProxy(string) (OwnerProxyState, error) {
	return OwnerProxyState{}, errors.New("OWNER_PROXY_WINDOWS_REQUIRED")
}
func CompareSetOwnerSystemProxy(string, OwnerProxyState, OwnerProxyState) error {
	return errors.New("OWNER_PROXY_WINDOWS_REQUIRED")
}
