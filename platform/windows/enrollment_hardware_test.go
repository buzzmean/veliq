package windowsplatform

import "testing"

func TestEnrollmentPhysicalWiredStableAcrossVPNAndDisconnectedWiFi(t *testing.T) {
	a := []enrollmentAdapter{{Index: 7, Type: 71, Up: false, MAC: "10-22-33-44-55-66"}, {Index: 14, Type: 6, Up: true, MAC: "10-11-22-33-44-55"}}
	// A virtual VPN owns the default route; no physical-route row remains.
	routes := []enrollmentRoute{{Index: 99, Metric: 1}}
	if got := selectEnrollmentAdapter(a, routes); got != "10:11:22:33:44:55" {
		t.Fatal("underlying Ethernet lost behind VPN")
	}
	a[0].Up = true
	routes = append(routes, enrollmentRoute{Index: 7, Metric: 0})
	if got := selectEnrollmentAdapter(a, routes); got != "10:22:33:44:55:66" {
		t.Fatal("existing physical default route changed identity")
	}
	a = append(a, enrollmentAdapter{Index: 3, Type: 6, Up: true, MAC: "10-33-44-55-66-77"})
	before := selectEnrollmentAdapter(a, nil)
	a[1].Index = 73
	a[2].Index = 2
	a[0], a[2] = a[2], a[0]
	if selectEnrollmentAdapter(a, nil) != before {
		t.Fatal("adapter order/Windows indexes changed identity")
	}
}
func TestEnrollmentAdapterSelectionBoundsAndFallback(t *testing.T) {
	if selectEnrollmentAdapter(nil, nil) != "" {
		t.Fatal("invented adapter")
	}
	a := []enrollmentAdapter{{Type: 6, Up: true, MAC: "00-00-00-00-00-00"}, {Type: 71, Up: true, MAC: "10-22-33-44-55-66"}}
	if selectEnrollmentAdapter(a, nil) != "10:22:33:44:55:66" {
		t.Fatal("valid physical WiFi fallback missing")
	}
}
