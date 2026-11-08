//go:build windows

package windowsplatform

import (
	"errors"
	"golang.org/x/sys/windows/registry"
)

// Read-only admission for the system PAC. It never edits an existing managed
// browser policy or mistakes a loopback address for ownership.
func OwnerBrowserProxyPolicyAvailable(sid string, edge bool, owned []string) error {
	path := `Software\Policies\Google\Chrome`
	if edge {
		path = edgePolicyPath
	}
	if err := browserMachinePolicyAbsent(path); err != nil {
		return errors.New("OWNER_PROXY_FOREIGN_BROWSER_POLICY")
	}
	k, err := registry.OpenKey(registry.USERS, sid+`\`+path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("OWNER_PROXY_BROWSER_POLICY_UNREADABLE")
	}
	defer k.Close()
	for _, name := range []string{"ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
		if _, _, err := k.GetValue(name, nil); !errors.Is(err, registry.ErrNotExist) {
			return errors.New("OWNER_PROXY_FOREIGN_BROWSER_POLICY")
		}
	}
	value, _, err := k.GetStringValue("ProxySettings")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("OWNER_PROXY_BROWSER_POLICY_UNREADABLE")
	}
	if !recognizedOwnedProxyValue(value, owned) {
		return errors.New("OWNER_PROXY_FOREIGN_BROWSER_POLICY")
	}
	return nil
}
