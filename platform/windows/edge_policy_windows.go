//go:build windows

package windowsplatform

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const edgePolicyPath = `Software\Policies\Microsoft\Edge`

// EdgeProxyPolicyWrite is called only by the installation-owner authenticated
// service IPC. It touches that owner's Edge policy, never HKCU of SYSTEM or Chrome.
// Foreign machine/user policy is refused, including split ProxyMode values.
func EdgeProxyPolicyWrite(sid string, owned []string, next string) error {
	return browserProxyPolicyWrite(sid, owned, next, edgePolicyPath)
}

// Chrome uses the same owner-only, foreign-policy refusing service writer.
func ChromeProxyPolicyWrite(sid string, owned []string, next string) error {
	return browserProxyPolicyWrite(sid, owned, next, `Software\Policies\Google\Chrome`)
}
func browserProxyPolicyWrite(sid string, owned []string, next, policyPath string) error {
	return browserProxyPolicyWriteNotify(sid, owned, next, policyPath, requestBrowserPolicyRefresh)
}
func browserProxyPolicyWriteNotify(sid string, owned []string, next, policyPath string, notify func(string)) error {
	if _, err := windows.StringToSid(sid); err != nil {
		return err
	}
	if !validEdgeProxyValue(next) {
		return errors.New("invalid owned Edge PAC")
	}
	if err := browserMachinePolicyAbsent(policyPath); err != nil {
		return err
	}
	// Never create a fake HKU\SID when SCM starts before owner logon.
	owner, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE)
	if err != nil {
		return errors.New("installation owner registry hive not loaded")
	}
	owner.Close()
	key, _, err := registry.CreateKey(registry.USERS, sid+`\`+policyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	for _, n := range []string{"ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
		if _, _, e := key.GetValue(n, nil); !errors.Is(e, registry.ErrNotExist) {
			return errors.New("foreign Edge proxy policy; no settings changed")
		}
	}
	current, _, err := key.GetStringValue("ProxySettings")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return errors.New("unreadable Edge proxy policy")
	}
	if err == nil {
		recognized := false
		for _, value := range owned {
			if value != "" && sameOwnedProxyValue(value, current) {
				recognized = true
			}
		}
		if !recognized {
			return errors.New("Edge proxy policy is managed by another owner; no settings changed")
		}
	}
	if current == next {
		return nil
	}
	if err = key.SetStringValue("ProxySettings", next); err != nil {
		return err
	}
	notify(sid)
	return nil
}
func edgeMachinePolicyAbsent() error { return browserMachinePolicyAbsent(edgePolicyPath) }
func browserMachinePolicyAbsent(policyPath string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, policyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()
	for _, n := range []string{"ProxySettings", "ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
		if _, _, e := key.GetValue(n, nil); !errors.Is(e, registry.ErrNotExist) {
			return errors.New("machine-managed Edge proxy policy; no settings changed")
		}
	}
	return nil
}
func EdgeProxyPolicyActive(sid, expected string) bool {
	if expected == "" || len(expected) > 128*1024 {
		return false
	}
	if _, err := windows.StringToSid(sid); err != nil {
		return false
	}
	if edgeMachinePolicyAbsent() != nil {
		return false
	}
	key, err := registry.OpenKey(registry.USERS, sid+`\`+edgePolicyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	for _, n := range []string{"ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
		if _, _, e := key.GetValue(n, nil); !errors.Is(e, registry.ErrNotExist) {
			return false
		}
	}
	raw, _, err := key.GetStringValue("ProxySettings")
	if err != nil || !validEdgeProxyValue(raw) {
		return false
	}
	var p struct {
		URL string `json:"ProxyPacUrl"`
	}
	_ = json.Unmarshal([]byte(raw), &p)
	return p.URL == expected
}

// Delete only this product's exact ProxySettings value. Never delete a key,
// split proxy policies, HKLM, WinINET/WinHTTP settings or another owner's value.
func ChromeProxyPolicyRemove(sid string, owned []string) error {
	return browserProxyPolicyRemove(sid, owned, `Software\Policies\Google\Chrome`)
}
func EdgeProxyPolicyRemove(sid string, owned []string) error {
	return browserProxyPolicyRemove(sid, owned, edgePolicyPath)
}
func browserProxyPolicyRemove(sid string, owned []string, policyPath string) error {
	return browserProxyPolicyRemoveNotify(sid, owned, policyPath, requestBrowserPolicyRefresh)
}
func browserProxyPolicyRemoveNotify(sid string, owned []string, policyPath string, notify func(string)) error {
	if _, err := windows.StringToSid(sid); err != nil {
		return errors.New("BROWSER_POLICY_OWNER_INVALID")
	}
	owner, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE)
	if err != nil {
		return errors.New("BROWSER_POLICY_OWNER_HIVE_UNAVAILABLE")
	}
	owner.Close()
	key, err := registry.OpenKey(registry.USERS, sid+`\`+policyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("BROWSER_POLICY_OWNER_HIVE_UNAVAILABLE")
	}
	defer key.Close()
	value, _, err := key.GetStringValue("ProxySettings")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("BROWSER_POLICY_VALUE_UNREADABLE")
	}
	if !recognizedOwnedProxyValue(value, owned) {
		return errors.New("BROWSER_FOREIGN_POLICY_PRESERVED")
	}
	if err = key.DeleteValue("ProxySettings"); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return errors.New("BROWSER_POLICY_REMOVE_FAILED")
	}
	notify(sid)
	return nil
}
