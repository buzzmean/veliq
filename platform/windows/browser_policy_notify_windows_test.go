//go:build windows

package windowsplatform

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"testing"
	"time"
)

func TestOwnedPolicyMutationNotifiesOnlyOnChangeAndPreservesKey(t *testing.T) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sid := user.User.Sid.String()
	path := fmt.Sprintf(`Software\VELIQTest\Notify-%d-%d`, os.Getpid(), time.Now().UnixNano())
	key, _, e := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if e != nil {
		t.Fatal(e)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	defer key.Close()
	const value = `{"ProxyMode":"pac_script","ProxyPacUrl":"data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5Rm9yVVJMKCl7cmV0dXJuICdESVJFQ1QnO30=","ProxyPacMandatory":true}`
	notifications := 0
	notify := func(owner string) {
		if owner != sid {
			t.Fatal("wrong owner")
		}
		notifications++
	}
	if e = browserProxyPolicyWriteNotify(sid, nil, value, path, notify); e != nil {
		t.Fatal(e)
	}
	if e = browserProxyPolicyWriteNotify(sid, []string{value}, value, path, notify); e != nil {
		t.Fatal(e)
	}
	if notifications != 1 {
		t.Fatal("same value caused refresh", notifications)
	}
	if e = browserProxyPolicyRemoveNotify(sid, []string{value}, path, notify); e != nil {
		t.Fatal(e)
	}
	if notifications != 2 {
		t.Fatal("delete did not notify", notifications)
	}
	reopened, e := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if e != nil {
		t.Fatal("policy key deleted", e)
	}
	reopened.Close()
	if e = browserProxyPolicyRemoveNotify(sid, []string{value}, path, notify); e != nil {
		t.Fatal(e)
	}
	if notifications != 2 {
		t.Fatal("absent value caused refresh")
	}
	key.SetStringValue("ProxySettings", `{"ProxyMode":"direct"}`)
	if e = browserProxyPolicyRemoveNotify(sid, []string{value}, path, notify); e == nil {
		t.Fatal("foreign policy removed")
	}
	if notifications != 2 {
		t.Fatal("foreign mutation notified")
	}
}
