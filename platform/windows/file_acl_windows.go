//go:build windows

package windowsplatform

import "golang.org/x/sys/windows"

// SYSTEM/Admins keep write access; only the installation owner gains read access
// to this non-secret policy file. Never use it for credentials or state folders.
func AllowOwnerReadFile(path, sid string) error {
	if _, err := windows.StringToSid(sid); err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + sid + ")")
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
