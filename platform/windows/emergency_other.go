//go:build !windows

package windowsplatform

import "os"

func ReadEmergencyVerifier() ([]byte,error) {return nil,os.ErrNotExist}
