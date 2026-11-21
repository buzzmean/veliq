//go:build windows

package windowsplatform

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/enrollment"
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
)

// Metadata only. No memory read/injection, MachineGuid, raw hardware logs or argv.
func EnrollmentHardware(ctx context.Context) (enrollment.Hardware, error) {
	script := `$ErrorActionPreference='Stop';$u='';$b='';$a=@();$r=@();try{$u=[string](Get-CimInstance Win32_ComputerSystemProduct).UUID}catch{};try{$b=[string](Get-CimInstance Win32_BaseBoard|Select-Object -First 1).SerialNumber}catch{};try{$a=@(Get-NetAdapter -Physical|Select-Object -First 129|ForEach-Object {@{index=[uint32]$_.ifIndex;type=[uint32]$_.InterfaceType;up=($_.Status -eq 'Up');mac=[string]$_.MacAddress}})}catch{};try{$r=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|Select-Object -First 129|ForEach-Object {@{index=[uint32]$_.ifIndex;metric=[uint32]$_.RouteMetric}})}catch{};@{uuid=$u;board_serial=$b;adapters=$a;routes=$r}|ConvertTo-Json -Compress -Depth 5`

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	raw, e := cmd.Output()
	if e != nil || len(raw) > 65536 {
		return enrollment.Hardware{}, errors.New("HARDWARE_ID_UNAVAILABLE")
	}
	var metadata enrollmentMetadata
	if json.Unmarshal(raw, &metadata) != nil || len(metadata.Adapters) > 128 || len(metadata.Routes) > 128 {
		return enrollment.Hardware{}, errors.New("HARDWARE_ID_UNAVAILABLE")
	}
	return metadata.hardware(), nil
}
func ProtectActivationFile(path string) error {
	d, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return e
	}
	acl, _, e := d.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
