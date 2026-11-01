//go:build windows

package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestQUICOriginNativeCaptureKeepsTCPFallback(t *testing.T) {
	owner := quicProbeOwner(t)
	for _, host := range []string{"www.youtube.com", "api.openai.com"} {
		t.Run(host, func(t *testing.T) {
			packets := captureQUICOriginFlight(t, host)
			b, _ := captureFixture(t)
			defer b.quicOrigins.clear()
			_, tuple, d := quicOriginScopeFixture()
			scope := quicProbeScopeFixture()
			scope.Owner = owner
			b.associations.Put(Association{Identity: owner, Tuple: tuple, Endpoint: 1})
			writes := 0
			b.packetWriter = func(p []byte, _ [80]byte) error {
				writes++
				if len(p) < 28 || p[9] != 1 || p[20] != 3 || p[21] != 3 {
					t.Fatal("original/fake escaped blocked browser flow")
				}
				return nil
			}
			for _, p := range packets {
				raw := quicProbePacket(scope, p)
				saved := bytes.Clone(raw)
				b.processUDP(nil, raw, [80]byte{}, func(id ProcessIdentity, got Tuple) Decision {
					if id != owner || got != tuple {
						t.Fatal("owner binding")
					}
					return d
				})
				if !bytes.Equal(raw, saved) {
					t.Fatal("original mutated")
				}
			}
			if writes != 1 || b.Drops.Load() != uint64(len(packets)) {
				t.Fatal("TCP fallback/drop count changed", writes, b.Drops.Load())
			}
			var observed bool
			for _, r := range b.CaptureIngressStatus().Records {
				if r.QUICOrigin != nil && r.QUICOrigin.Complete {
					observed = r.QUICOrigin.Domain == host && r.PID == owner.PID && r.Birth == owner.CreationTime && r.Decision == "UDP443_BLOCK"
				}
			}
			if !observed || !b.flows[tuple].decision.Block || b.flows[tuple].decision.OriginDomain != "" {
				t.Fatal("missing scoped observation or altered policy")
			}
			t.Logf("native owner=true host=%s Initials=%d ICMP=%d original_forwarded=0 protected_or_DPI_still_blocked=true", host, len(packets), writes)
		})
	}
}

func TestQUICFlowNativeCaptureFreshTriggerOnly(t *testing.T) {
	owner := quicProbeOwner(t)
	packets := captureQUICOriginFlight(t, "www.youtube.com")
	for _, mode := range []string{"fresh", "late-FLOW", "no-FLOW", "stale-FLOW", "deleted", "policy-change"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := captureFixture(t)
			defer b.quicOrigins.clear()
			_, tuple, d := quicOriginScopeFixture()
			scope := quicProbeScopeFixture()
			scope.Owner = owner
			b.associations.Put(Association{Identity: owner, Tuple: tuple, Endpoint: 7})
			tick, freq := quicOwnerClock()
			if freq <= 0 {
				t.Fatal("QPC unavailable")
			}
			flowTick := tick
			if mode == "stale-FLOW" {
				flowTick -= 3 * freq
			}
			if mode != "no-FLOW" && mode != "late-FLOW" {
				b.quicFlows.established(tuple, owner, 7, flowTick, time.Now())
			}
			claims, icmp := 0, 0
			var trigger QUICProbeTrigger
			d.QUICProbe = func(tr QUICProbeTrigger) {
				if tr.Claim() {
					claims++
					trigger = tr
				}
			}
			b.packetWriter = func(p []byte, _ [80]byte) error {
				icmp++
				if p[9] != 1 {
					t.Fatal("browser original forwarded")
				}
				return nil
			}
			for i, p := range packets {
				tick, _ = quicOwnerClock()
				var addr [80]byte
				binary.LittleEndian.PutUint64(addr[:8], uint64(tick))
				b.processUDP(nil, quicProbePacket(scope, p), addr, func(ProcessIdentity, Tuple) Decision { return d })
				if i == 0 {
					if mode == "late-FLOW" {
						b.quicFlows.established(tuple, owner, 7, tick, time.Now())
					}
					if mode == "deleted" {
						b.quicFlows.deleted(tuple, 7)
					}
					if mode == "policy-change" {
						b.policyEpoch.Add(1)
					}
				}
			}
			want := 0
			if mode == "fresh" {
				want = 1
			}
			if claims != want || icmp != 1 || b.Drops.Load() != uint64(len(packets)) {
				t.Fatal("claim/block contract", claims, icmp, b.Drops.Load())
			}
			if mode == "fresh" {
				b.quicFlows.deleted(tuple, 7)
				if !trigger.Current() {
					t.Fatal("source close invalidated owned probe")
				}
				b.policyEpoch.Add(1)
				if trigger.Current() {
					t.Fatal("policy generation did not revoke owned probe")
				}
			}
			t.Logf("mode=%s Initials=%d claims=%d ICMP=%d original_forwarded=0", mode, len(packets), claims, icmp)
		})
	}
}
