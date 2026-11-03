//go:build windows

package windowsplatform

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const emergencyRegistryPath = `SOFTWARE\VELIQ\EmergencyExit`

// The verifier lives in the 64-bit machine registry, outside the user-writable
// profile. Validate owner and DACL on the open key used to read the value.
func ReadEmergencyVerifier() ([]byte,error) {
	key,err:=registry.OpenKey(registry.LOCAL_MACHINE,emergencyRegistryPath,registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL)
	if errors.Is(err,windows.ERROR_FILE_NOT_FOUND) {return nil,os.ErrNotExist}
	if err!=nil {return nil,err}
	defer key.Close()
	sd,err:=windows.GetSecurityInfo(windows.Handle(key),windows.SE_REGISTRY_KEY,windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err!=nil {return nil,err}
	if !emergencyRegistrySecurityValid(sd) {return nil,errors.New("EMERGENCY_REGISTRY_UNTRUSTED")}
	buf:=make([]byte,4097)
	n,kind,err:=key.GetValue("Verifier",buf)
	if errors.Is(err,windows.ERROR_FILE_NOT_FOUND) {return nil,os.ErrNotExist}
	if err!=nil || kind!=registry.BINARY || n==0 || n>4096 {clear(buf);return nil,errors.New("EMERGENCY_VERIFIER_UNAVAILABLE")}
	return buf[:n],nil
}
func emergencyRegistrySecurityValid(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd==nil {return false}
	owner,_,err:=sd.Owner()
	if err!=nil || owner==nil || (owner.String()!="S-1-5-18" && owner.String()!="S-1-5-32-544") {return false}
	control,_,err:=sd.Control()
	if err!=nil || control&windows.SE_DACL_PROTECTED==0 {return false}
	acl,_,err:=sd.DACL()
	if err!=nil || acl==nil || acl.AceCount!=2 {return false}
	found:=map[string]bool{}
	for i:=uint32(0);i<uint32(acl.AceCount);i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl,i,&ace)!=nil || ace==nil || ace.Header.AceType!=windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags & ^uint8(windows.CONTAINER_INHERIT_ACE)!=0 || uint32(ace.Mask)!=registry.ALL_ACCESS {return false}
		sid:=(*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if (sid!="S-1-5-18" && sid!="S-1-5-32-544") || found[sid] {return false}
		found[sid]=true
	}
	return found["S-1-5-18"] && found["S-1-5-32-544"]
}
