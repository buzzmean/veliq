package windowsplatform

import "testing"

func TestSilentOwnedPolicyEquivalentOnlyForExactMandatoryPAC(t *testing.T) {
	a := `{"ProxyMode":"pac_script","ProxyPacUrl":"data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5Rm9yVVJMKCl7cmV0dXJuICdESVJFQ1QnO30=","ProxyPacMandatory":true}`
	b := `{"ProxyPacMandatory":true,"ProxyPacUrl":"data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5Rm9yVVJMKCl7cmV0dXJuICdESVJFQ1QnO30=","ProxyMode":"pac_script"}`
	if !sameOwnedProxyValue(a, b) {
		t.Fatal("legacy C# and Go ordering conflict")
	}
	for _, other := range []string{a[:len(a)-1] + `,"ProxyBypassList":"*"}`, `{"ProxyMode":"direct"}`, `{"ProxyMode":"pac_script","ProxyPacUrl":"https://foreign.invalid/pac","ProxyPacMandatory":true}`} {
		if sameOwnedProxyValue(a, other) {
			t.Fatal("foreign/changed policy was adopted")
		}
	}
}
