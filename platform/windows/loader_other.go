//go:build !windows

package windowsplatform

type DriverFiles struct {
	Directory    string `json:"directory"`
	DLLSHA256    string `json:"dll_sha256"`
	DriverSHA256 string `json:"driver_sha256"`
}
