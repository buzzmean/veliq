//go:build windows

package windowsplatform

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActivationFileACLOnlySystemAndAdministrators(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activation.fixture")
	if e := os.WriteFile(path, []byte("nonsecret-fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := ProtectActivationFile(path); e != nil {
		t.Fatal(e)
	}
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	s := sd.String()
	if !strings.Contains(s, "D:P") || !strings.Contains(s, ";;;SY)") || !strings.Contains(s, ";;;BA)") {
		t.Fatal("expected protected SYSTEM/admin ACL", s)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if acl.AceCount != 2 {
		t.Fatal("unexpected additional ACL principals", acl.AceCount)
	}
}
