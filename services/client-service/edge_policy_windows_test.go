//go:build windows

package clientservice

import (
	"errors"
	"os"
	"testing"

	wp "github.com/buzzmean/veliq/platform/windows"
	"golang.org/x/sys/windows/registry"
)

func TestEdgePolicyRefusesForeignAndWrongOwnerSID(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_EDGE_POLICY") != "1" {
		t.Skip("disposable native policy acceptance only")
	}
	self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	sid, err := wp.ProcessUserSID(self)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Policies\Microsoft\Edge`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	for _, name := range []string{"ProxySettings", "ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
		if _, _, err := key.GetValue(name, nil); !errors.Is(err, registry.ErrNotExist) {
			t.Fatal("refusing existing Edge policy", name)
		}
	}
	if err = key.SetStringValue("ProxyMode", "direct"); err != nil {
		t.Fatal(err)
	}
	defer key.DeleteValue("ProxyMode")
	owned := edgePolicyValue(edgeClosedPAC(edgeTestProfile()))
	if err = wp.EdgeProxyPolicyWrite(sid, nil, owned); err == nil {
		t.Fatal("foreign policy overwritten")
	}
	if value, _, _ := key.GetStringValue("ProxyMode"); value != "direct" {
		t.Fatal("foreign policy altered")
	}
	if _, _, err := key.GetValue("ProxySettings", nil); !errors.Is(err, registry.ErrNotExist) {
		t.Fatal("partial Edge write")
	}
	if err = wp.EdgeProxyPolicyWrite("invalid-owner-sid", nil, owned); err == nil {
		t.Fatal("invalid SID admitted")
	}
}
