package windowsplatform

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func validEdgeProxyValue(raw string) bool {
	if len(raw) > 256*1024 {
		return false
	}
	var p struct {
		Mode      string `json:"ProxyMode"`
		URL       string `json:"ProxyPacUrl"`
		Mandatory bool   `json:"ProxyPacMandatory"`
	}
	if json.Unmarshal([]byte(raw), &p) != nil || p.Mode != "pac_script" || !p.Mandatory {
		return false
	}
	const prefix = "data:application/x-ns-proxy-autoconfig;base64,"
	if !strings.HasPrefix(p.URL, prefix) || len(p.URL) > 128*1024 {
		return false
	}
	b, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(p.URL, prefix))
	return e == nil && len(b) > 0 && strings.Contains(string(b), "FindProxyForURL")
}

// Serialization order differs between the old C# owner journal and Go. Only
// validated mandatory inline PAC values with exactly the same URL are equivalent.
func sameOwnedProxyValue(a, b string) bool {
	var keysA, keysB map[string]json.RawMessage
	if json.Unmarshal([]byte(a), &keysA) != nil || json.Unmarshal([]byte(b), &keysB) != nil || len(keysA) != 3 || len(keysB) != 3 {
		return false
	}
	if !validEdgeProxyValue(a) || !validEdgeProxyValue(b) {
		return false
	}
	var x, y struct {
		URL string `json:"ProxyPacUrl"`
	}
	_ = json.Unmarshal([]byte(a), &x)
	_ = json.Unmarshal([]byte(b), &y)
	return x.URL == y.URL
}

func recognizedOwnedProxyValue(current string, owned []string) bool {
	if len(owned) > 8 {
		return false
	}
	for _, v := range owned {
		if sameOwnedProxyValue(current, v) {
			return true
		}
	}
	return false
}
