//go:build windows

package windowsplatform

import (
	"bytes"
	"testing"
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
