package gameudp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
)

func recordTarget(q *TargetQuality, network, route, address string, dst netip.AddrPort, now time.Time, rtt time.Duration, losses int) {
	for round := range targetQualityRounds {
		at := now.Add(time.Duration(round-targetQualityRounds) * time.Second)
		m := optimizer.RouteMeasurement{Target: dst, Network: network, RouteID: route, RouteAddress: address,
			AuthenticatedTarget: true, ObservedAt: at}
		for i := range 5 {
			probe := optimizer.ProbeSample{At: at, Outcome: optimizer.Reply, RTT: rtt}
			if i*targetQualityRounds+round < losses {
				probe.Outcome, probe.RTT = optimizer.Timeout, 0
			}
			m.Probes = append(m.Probes, probe)
		}
		q.Observe(m)
	}
}

func TestGameTargetQualityRequiresRTTAndLoss(t *testing.T) {
	now := time.Unix(1000, 0)
	dst := netip.MustParseAddrPort("18.157.46.1:7766")
	q := &TargetQuality{}
	recordTarget(q, "network1", optimizer.Direct, "", dst, now, 70*time.Millisecond, 5)
	recordTarget(q, "network1", "lower-rtt-only", "relay1", dst, now, 25*time.Millisecond, 5)
	recordTarget(q, "network1", "lower-loss-only", "relay2", dst, now, 75*time.Millisecond, 0)
	recordTarget(q, "network1", "retired-fast", "relay3", dst, now, 10*time.Millisecond, 0)
	recordTarget(q, "network1", "wrong-endpoint", "relay4", netip.MustParseAddrPort("18.157.46.1:7767"), now, 25*time.Millisecond, 0)
	configured := map[string]string{"lower-rtt-only": "relay1", "lower-loss-only": "relay2", "retired-fast": "replaced", "wrong-endpoint": "relay4"}
	if got := q.Compare("network1", dst, configured, now); got.Relay != "" || len(got.Samples) != 3 {
		t.Fatal(got)
	}
	recordTarget(q, "network1", "new-relay", "relay5", dst, now, 40*time.Millisecond, 1)
	configured["new-relay"] = "relay5"
	got := q.Compare("network1", dst, configured, now)
	if got.Relay != "new-relay" || got.State != TargetQualityRelayReason {
		t.Fatal(got)
	}
	t.Logf("same endpoint %s; DIRECT RTT 70ms, loss 25%%; new configured relay RTT 40ms, loss 5%%; 20 authenticated simulated samples per route", dst)
	if q.Compare("network2", dst, configured, now).Relay != "" || q.Compare("network1", dst, configured, now.Add(time.Minute)).Relay != "" {
		t.Fatal("stale or different network measurements selected a relay")
	}
}

func TestGameTargetQualityNewFlowsOnly(t *testing.T) {
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
	if err != nil || pref.e.Stage != Relay || pref.e.Selection != MeasuredRelaySelection || direct.e.Stage != Direct {
		t.Fatal(pref, err, direct.e)
	}
	sustain(engine, pref, now.Add(6*time.Second))
	if got := ladderFlow(t, engine, now.Add(12*time.Second), 50002); got.e.Stage != Direct {
		t.Fatal("relay recommendation outlived quality proof", got.e)
	}
	failTrial(engine, direct, now.Add(12*time.Second))
	key.Destination = netip.MustParseAddrPort("18.157.46.2:7766")
	other, err := engine.Open(key, now.Add(20*time.Second))
	if err != nil || other.e.Stage != Direct {
		t.Fatal("an endpoint failure crossed to another endpoint", other, err)
	}
	engine.SetLocalOnly(true)
	local, err := engine.OpenWithQuality(direct.key, now.Add(20*time.Second), "new-relay")
	if err != nil || local.e.Stage == Relay {
		t.Fatal("quality evidence overrode local-only", local, err)
	}
}
