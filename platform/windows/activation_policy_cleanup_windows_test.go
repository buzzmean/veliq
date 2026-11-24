//go:build windows

package windowsplatform

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/browserproxy"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"strings"
	"testing"
	"time"
)

func TestActivationOwnedPolicyCleanupPreservesForeignSettings(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`Software\VELIQTest\ActivationCleanup-%d-%d`, os.Getpid(), time.Now().UnixNano())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	defer k.Close()
	owned := `{"ProxyMode":"pac_script","ProxyPacUrl":"data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5Rm9yVVJMKCl7cmV0dXJuICdESVJFQ1QnO30=","ProxyPacMandatory":true}`
	if err = k.SetStringValue("ProxySettings", owned); err != nil {
		t.Fatal(err)
	}
	k.SetStringValue("ProxyMode", "foreign")
	if err = browserProxyPolicyRemove(user.User.Sid.String(), []string{owned}, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = k.GetStringValue("ProxySettings"); err != registry.ErrNotExist {
		t.Fatal("owned value survived")
	}
	if v, _, _ := k.GetStringValue("ProxyMode"); v != "foreign" {
		t.Fatal("split foreign value changed")
	}
	if err = browserProxyPolicyRemove(user.User.Sid.String(), []string{owned}, path); err != nil {
		t.Fatal("repeat cleanup", err)
	}
	k.SetStringValue("ProxySettings", `{"ProxyMode":"direct"}`)
	if err = browserProxyPolicyRemove(user.User.Sid.String(), []string{owned}, path); err == nil {
		t.Fatal("foreign policy accepted")
	}
	if v, _, _ := k.GetStringValue("ProxySettings"); v != `{"ProxyMode":"direct"}` {
		t.Fatal("foreign policy changed")
	}
}

// Native registry contract on an isolated test key, never a real browser policy.
func TestActivationAvailabilityPACRegistryCleanup(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`Software\VELIQTest\Availability-%d-%d`, os.Getpid(), time.Now().UnixNano())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	defer key.Close()
	args, err := browserproxy.ChromeArgumentsWithRecovery("127.0.0.1:1234", "fixture", nil, false, "127.0.0.1:1235")
	if err != nil {
		t.Fatal(err)
	}
	pac, err := browserproxy.AvailabilityPAC(strings.TrimPrefix(args[1], "--proxy-pac-url="))
	if err != nil {
		t.Fatal(err)
	}
	script, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, "data:application/x-ns-proxy-autoconfig;base64,"))
	if !strings.Contains(string(script), "; DIRECT") {
		t.Fatal("fallback absent")
	}
	raw, _ := json.Marshal(map[string]any{"ProxyMode": "pac_script", "ProxyPacUrl": pac, "ProxyPacMandatory": true})
	value := string(raw)
	if !validEdgeProxyValue(value) {
		t.Fatal("mandatory PAC with explicit DIRECT rejected")
	}
	if err = key.SetStringValue("ProxySettings", value); err != nil {
		t.Fatal(err)
	}
	if err = browserProxyPolicyRemove(user.User.Sid.String(), []string{value}, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = key.GetStringValue("ProxySettings"); err != registry.ErrNotExist {
		t.Fatal("not-ready policy survived cleanup")
	}
}
