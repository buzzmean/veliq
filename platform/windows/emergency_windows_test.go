//go:build windows
package windowsplatform
import (
	"testing"
	"golang.org/x/sys/windows"
)
func TestEmergencyVerifierRejectsGuestWritableOrOwnedKeys(t *testing.T) {
	for _,test:=range []struct{sddl string;ok bool}{
		{"O:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)",true},
		{"O:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)",true},
		{"O:BUD:P(A;;KA;;;SY)(A;;KA;;;BA)",false},
		{"O:BAD:(A;;KA;;;SY)(A;;KA;;;BA)",false},
		{"O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)",false},
		{"O:BAD:P(A;;KR;;;SY)(A;;KA;;;BA)",false},
		{"O:BAD:P(A;IO;KA;;;SY)(A;;KA;;;BA)",false},
		{"O:BAD:P(A;;KA;;;BA)(A;;KA;;;BA)",false},
	} {
		sd,err:=windows.SecurityDescriptorFromString(test.sddl);if err!=nil {t.Fatal(err)}
		if emergencyRegistrySecurityValid(sd)!=test.ok {t.Errorf("security validation: %s",test.sddl)}
	}
}
