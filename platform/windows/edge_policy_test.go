package windowsplatform

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestEdgePolicyRequiresMandatoryInlinePAC(t *testing.T) {
	pac := "data:application/x-ns-proxy-autoconfig;base64," + base64.StdEncoding.EncodeToString([]byte("function FindProxyForURL(){return 'DIRECT';}"))
	for _, tc := range []struct {
		mode, url     string
		mandatory, ok bool
	}{
		{"pac_script", pac, true, true}, {"pac_script", pac, false, false}, {"direct", pac, true, false}, {"pac_script", "http://foreign/pac", true, false}, {"pac_script", "data:application/x-ns-proxy-autoconfig;base64,broken", true, false},
	} {
		raw, _ := json.Marshal(map[string]any{"ProxyMode": tc.mode, "ProxyPacUrl": tc.url, "ProxyPacMandatory": tc.mandatory})
		if validEdgeProxyValue(string(raw)) != tc.ok {
			t.Fatal(tc)
		}
	}
}
