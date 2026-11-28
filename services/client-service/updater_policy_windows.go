//go:build windows

package clientservice

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const managedUpdatePolicyKey = `SOFTWARE\VELIQ\ClubUpdates`

func readManagedUpdatePolicy() (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, managedUpdatePolicyKey, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer key.Close()
	return readManagedUpdatePolicyKey(key)
}

func readManagedUpdatePolicyKey(key registry.Key) (bool, error) {
	sd, err := windows.GetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	if !managedUpdatePolicyACL(sd) {
		return false, errors.New("UPDATE_POLICY_UNTRUSTED")
	}
	version, kind, err := key.GetIntegerValue("Version")
	if err != nil || kind != registry.DWORD || version != 1 {
		return false, errors.New("UPDATE_POLICY_INVALID")
	}
	enabled, kind, err := key.GetIntegerValue("AutoInstall")
	if err != nil || kind != registry.DWORD || enabled > 1 {
		return false, errors.New("UPDATE_POLICY_INVALID")
	}
	return enabled == 1, nil
}

// No user-owned or user-writable policy can authorize a SYSTEM installer.
func managedUpdatePolicyACL(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || (owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 2 {
		return false
	}
	found := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags & ^uint8(windows.CONTAINER_INHERIT_ACE) != 0 || uint32(ace.Mask) != registry.ALL_ACCESS {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if (sid != "S-1-5-18" && sid != "S-1-5-32-544") || found[sid] {
			return false
		}
		found[sid] = true
	}
	return found["S-1-5-18"] && found["S-1-5-32-544"]
}
