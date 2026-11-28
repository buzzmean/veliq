//go:build windows

package clientservice

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestManagedUpdatePolicyRejectsUserWritableOrUnownedDescriptors(t *testing.T) {
	cases := []struct {
		sddl string
		ok   bool
	}{
		{"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)", true},
		{"O:SYG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)", true},
		{"O:BAG:BAD:(A;;KA;;;SY)(A;;KA;;;BA)", false},
		{"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;BU)", false},
		{"O:BAG:BAD:P(A;;KA;;;SY)", false},
		{"O:BUG:BUD:P(A;;KA;;;SY)(A;;KA;;;BA)", false},
		{"O:BAG:BAD:P(A;;KA;;;SY)(A;;KR;;;BA)", false},
	}
	for _, tc := range cases {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if got := managedUpdatePolicyACL(sd); got != tc.ok {
			t.Errorf("descriptor %s: got %v", tc.sddl, got)
		}
	}
	if managedUpdatePolicyACL(nil) {
		t.Fatal("nil accepted")
	}
}

func TestManagedUpdatePolicyNativeRegistryValuesAndACL(t *testing.T) {
	// Isolated per-test HKCU key. Never read or modify the machine policy.
	path := fmt.Sprintf(`Software\VELIQ-Update-Policy-Test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		key.Close()
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Error(err)
		}
	}()
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version, enabled uint32
		want             bool
		invalid          bool
	}{
		{1, 1, true, false}, {1, 0, false, false}, {2, 1, false, true}, {1, 2, false, true},
	} {
		if err = key.SetDWordValue("Version", tc.version); err != nil {
			t.Fatal(err)
		}
		if err = key.SetDWordValue("AutoInstall", tc.enabled); err != nil {
			t.Fatal(err)
		}
		got, err := readManagedUpdatePolicyKey(key)
		if got != tc.want || (err != nil) != tc.invalid {
			t.Fatalf("version=%d enabled=%d: %v %v", tc.version, tc.enabled, got, err)
		}
	}
	if err = key.SetDWordValue("Version", 1); err != nil {
		t.Fatal(err)
	}
	if err = key.SetStringValue("AutoInstall", "1"); err != nil {
		t.Fatal(err)
	}
	if ok, err := readManagedUpdatePolicyKey(key); ok || err == nil {
		t.Fatal("string enabled accepted")
	}
}
