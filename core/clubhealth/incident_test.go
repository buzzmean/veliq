package clubhealth

import "testing"

func TestClassifyIncidentRequiresPositiveEvidence(t *testing.T) {
	cases := []struct {
		name  string
		obs   IncidentObservation
		alert bool
		scope string
	}{
		{"heartbeat alone", IncidentObservation{Kind: IncidentHeartbeatGap}, false, ""},
		{"LAN outage with Internet up", IncidentObservation{Kind: IncidentLanGame, WindowsLive: Available, DirectInternet: Available, Confirmed: true}, false, ""},
		{"shutdown despite sustained outage", IncidentObservation{Kind: IncidentShutdown, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Sustained: true}, false, ""},
		{"correlated WAN loss", IncidentObservation{Kind: IncidentVELIQCP, WindowsLive: Available, DirectInternet: Failed, Confirmed: true, Sustained: true, ComponentReachability: Failed, ObserverReachability: Failed}, false, ""},
		{"confirmed crash", IncidentObservation{Kind: IncidentVELIQCrash, WindowsLive: Available, DirectInternet: Available, Confirmed: true}, true, ""},
		{"planned restart", IncidentObservation{Kind: IncidentVELIQCrash, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Planned: true}, false, ""},
		{"capture off", IncidentObservation{Kind: IncidentCapture, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Sustained: true}, false, ""},
		{"capture failed", IncidentObservation{Kind: IncidentCapture, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Sustained: true, OptimizationRequested: true}, true, ""},
		{"successful fallback", IncidentObservation{Kind: IncidentCapture, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Sustained: true, OptimizationRequested: true, RecoveredWithFallback: true}, false, ""},
		{"CP path only", IncidentObservation{Kind: IncidentVELIQCP, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Sustained: true, ComponentReachability: Failed, ObserverReachability: Available}, true, "network_path"},
		{"relay-wide", IncidentObservation{Kind: IncidentVELIQRelay, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Sustained: true, ComponentReachability: Failed, ObserverReachability: Failed}, true, "component"},
		{"CP no independent observation", IncidentObservation{Kind: IncidentVELIQCP, WindowsLive: Available, DirectInternet: Available, Confirmed: true, Sustained: true, ComponentReachability: Failed}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyIncident(tc.obs)
			if got.Alert != tc.alert || got.Scope != tc.scope {
				t.Fatalf("got %+v, want alert=%v scope=%q", got, tc.alert, tc.scope)
			}
		})
	}
}

func TestProtectedRelayFactIsNotInferredFromProximity(t *testing.T) {
	d := ProtectedRelayEvidence{Protected: ProtectedLanGame, DeviceID: "aaaaaaaaaaaaaaaa", Epoch: "bbbbbbbbbbbbbbbb", FlowID: "cccccccccccccccc", OpenID: "dddddddddddddddd", Sequence: 12, Stage: RelayAttempted}
	fact := RelayFact{DeviceID: "aaaaaaaaaaaaaaaa", Epoch: "bbbbbbbbbbbbbbbb", FlowID: "cccccccccccccccc", OpenID: "dddddddddddddddd", Sequence: 13, Authenticated: true, Bytes: 7}
	cases := []struct {
		name   string
		change func(*ProtectedRelayEvidence, *RelayFact)
		stage  RelayStage
	}{
		{"matching relayed bytes", func(*ProtectedRelayEvidence, *RelayFact) {}, RelayRelayed},
		{"confirmed open only", func(_ *ProtectedRelayEvidence, f *RelayFact) { f.Bytes = 0 }, RelayOpened},
		{"untrusted fact", func(_ *ProtectedRelayEvidence, f *RelayFact) { f.Authenticated = false }, RelayAttempted},
		{"other device", func(_ *ProtectedRelayEvidence, f *RelayFact) { f.DeviceID = "eeeeeeeeeeeeeeee" }, RelayAttempted},
		{"same flow ID after restart", func(_ *ProtectedRelayEvidence, f *RelayFact) { f.Epoch = "ffffffffffffffff" }, RelayAttempted},
		{"other flow", func(_ *ProtectedRelayEvidence, f *RelayFact) { f.FlowID = "abababababababab" }, RelayAttempted},
		{"another open on same flow", func(_ *ProtectedRelayEvidence, f *RelayFact) { f.OpenID = "cdcdcdcdcdcdcdcd" }, RelayAttempted},
		{"out of order", func(_ *ProtectedRelayEvidence, f *RelayFact) { f.Sequence = 11 }, RelayAttempted},
		{"guarded attempt never says relayed", func(d *ProtectedRelayEvidence, _ *RelayFact) { d.Stage = RelayBlocked }, RelayBlocked},
		{"unknown traffic class", func(d *ProtectedRelayEvidence, _ *RelayFact) { d.Protected = "" }, ""},
		{"missing open ID", func(d *ProtectedRelayEvidence, f *RelayFact) { d.OpenID, f.OpenID = "", "" }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, y := d, fact
			tc.change(&x, &y)
			got := ClassifyIncident(IncidentObservation{Kind: IncidentProtectedRoute, ProtectedDecision: x, RelayFact: y, WindowsLive: Unknown})
			if got.RouteStage != tc.stage || got.Alert != (tc.stage == RelayRelayed) {
				t.Fatalf("got %+v, want stage %q", got, tc.stage)
			}
		})
	}
}

func TestClientCannotClaimIndependentEvidence(t *testing.T) {
	v := IncidentObservation{Kind: IncidentVELIQCP, WindowsLive: Available, DirectInternet: Available, ComponentReachability: Failed}
	if !v.ValidClient() {
		t.Fatal("valid observation rejected")
	}
	v.ObserverReachability = Available
	if v.ValidClient() {
		t.Fatal("client supplied an independent observer")
	}
	v.ObserverReachability = Unknown
	v.DirectInternet = Signal(255)
	if v.ValidClient() {
		t.Fatal("unknown enum admitted")
	}
}
