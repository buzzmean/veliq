package gameudp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
)

func recordTarget(q *TargetQuality, network, route, address string, dst netip.AddrPort, now time.Time, rtt, tail time.Duration, losses int) {
	for round := range targetQualityRounds {
		at := now.Add(time.Duration(round-targetQualityRounds) * time.Second)
		m := optimizer.RouteMeasurement{Target: dst, Network: network, RouteID: route, RouteAddress: address,
			AuthenticatedTarget: true, ObservedAt: at}
		for i := range 5 {
			probe := optimizer.ProbeSample{At: at, Outcome: optimizer.Reply, RTT: rtt}
			if i == 4 && tail > 0 {
				probe.RTT = tail
			}
			if i*targetQualityRounds+round < losses {
				probe.Outcome, probe.RTT = optimizer.Timeout, 0
			}
			m.Probes = append(m.Probes, probe)
		}
		q.Observe(m)
	}
}

func TestGameTargetQualityRanksRelayLossThenTailLatency(t *testing.T) {
	now := time.Unix(1000, 0)
	dst := netip.MustParseAddrPort("18.157.46.1:7766")
	q := &TargetQuality{}
	recordTarget(q, "network1", "fast-lossy", "relay1", dst, now, 25*time.Millisecond, 0, 5)
	recordTarget(q, "network1", "steady", "relay2", dst, now, 75*time.Millisecond, 0, 0)
	recordTarget(q, "network1", "spiky", "relay3", dst, now, 40*time.Millisecond, 180*time.Millisecond, 0)
	recordTarget(q, "network1", "retired-fast", "relay4", dst, now, 10*time.Millisecond, 0, 0)
	recordTarget(q, "network1", "wrong-endpoint", "relay5", netip.MustParseAddrPort("18.157.46.1:7767"), now, 10*time.Millisecond, 0, 0)
	configured := map[string]string{"fast-lossy": "relay1", "steady": "relay2", "spiky": "relay3", "retired-fast": "replaced", "wrong-endpoint": "relay5"}
	if !q.HasTarget("network1", dst) {
		t.Fatal("exact relay measurements disappeared without a direct baseline")
	}
	if got := q.Compare("network1", dst, configured, now); got.Relay != "steady" || got.State != TargetQualityRelayReason || len(got.Samples) != 3 {
		t.Fatal(got)
	}
	recordTarget(q, "network1", optimizer.Direct, "", dst, now, 0, 0, 20)
	if got := q.Compare("network1", dst, configured, now); got.Relay != "steady" || len(got.Samples) != 3 {
		t.Fatal(got)
	}
	if q.Compare("network2", dst, configured, now).Relay != "" || q.Compare("network1", dst, configured, now.Add(time.Minute)).Relay != "" {
		t.Fatal("stale or different network measurements selected a relay")
	}
}

func TestGameTargetQualityDoesNotDisplaceHealthyDirectOrLocal(t *testing.T) {
	engine := NewLadder(nil)
	engine.SetEndpointScoped()
	engine.Configure(app, true)
	engine.SetReason("")
	now := time.Unix(1000, 0)
	direct := ladderFlow(t, engine, now, 50000)
	sustain(engine, direct, now)
	key := direct.key
	key.Source = netip.AddrPortFrom(key.Source.Addr(), 50001)
	pref, err := engine.OpenWithQuality(key, now.Add(6*time.Second), "new-relay")
	if err != nil || pref.e.Stage != Direct || pref.e.Selection == MeasuredRelaySelection || direct.e.Stage != Direct {
		t.Fatal(pref, err, direct.e)
	}
	failTrial(engine, direct, now.Add(12*time.Second))
	local, err := engine.OpenWithQuality(key, now.Add(20*time.Second), "new-relay")
	if err != nil || local.e.Stage != Local {
		t.Fatal("measurement skipped the first local trial", local, err)
	}
	sustain(engine, local, now.Add(20*time.Second))
	key.Source = netip.AddrPortFrom(key.Source.Addr(), 50002)
	healthy, err := engine.OpenWithQuality(key, now.Add(25*time.Second), "new-relay")
	learned := engine.Snapshot().Learning
	if err != nil || healthy.e.Stage != Local || len(learned) != 1 || !learned[0].Confirmed {
		t.Fatal("measurement displaced a healthy local route", healthy, err)
	}
	key.Destination = netip.MustParseAddrPort("18.157.46.2:7766")
	other, err := engine.OpenWithQuality(key, now.Add(25*time.Second), "new-relay")
	if err != nil || other.e.Stage != Direct {
		t.Fatal("an endpoint failure crossed to another endpoint", other, err)
	}
	engine.SetLocalOnly(true)
	localOnly, err := engine.OpenWithQuality(direct.key, now.Add(26*time.Second), "new-relay")
	if err != nil || localOnly.e.Stage == Relay {
		t.Fatal("quality evidence overrode local-only", localOnly, err)
	}
}
