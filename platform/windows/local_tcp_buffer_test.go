package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/routing"
	"net/netip"
	"testing"
	"time"
)

func TestBufferedNativeTCPContextsCountersAndFailOpen(t *testing.T) {
	hello := localTestHello(t)
	for _, kind := range []string{"success", "timeout", "fin", "rst", "send-failure", "old-generation", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			e := localstrategy.New()
			p := localstrategy.Profile{ID: "chain", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, Domains: []string{"www.youtube.com"}, Strategy: "chain", Actions: []localstrategy.Action{{Kind: "fake-tls", TTL: 5}, {Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1, 5}}, {Kind: "tcp-disorder"}}, Cutoff: 1, Enabled: true}
			if err := e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{p}}); err != nil {
				t.Fatal(err)
			}
			d := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: e, LocalStrategyID: "chain"}
			id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chosen.exe"}
			tuple := Tuple{"tcp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.9:443")}
			l := NewEvidenceLedger()
			st := &localstrategy.State{}
			b := &LocalTCPBuffer{}
			now := time.Now()
			syn := localTCPPacket(2, nil)
			binary.BigEndian.PutUint32(syn[24:], 99)
			if err := b.Push(d, st, id, tuple, syn, func([]byte) error { return nil }, l, now); err != nil {
				t.Fatal(err)
			}
			st.ConfirmHandshake(100, 199)
			cut := len(hello) / 2
			parts := [][]byte{hello[:cut], hello[cut:]}
			originals := [][]byte{}
			sent := [][]byte{}
			calls := 0
			for i, data := range parts {
				if i == 1 {
					switch kind {
					case "timeout":
						if !b.Expired(now.Add(localstrategy.HelloDeadline)) {
							t.Fatal("not expired")
						}
						if err := b.Flush(d, st, id, tuple, now.Add(localstrategy.HelloDeadline), "REASSEMBLY_TIMEOUT", l); err != nil {
							t.Fatal(err)
						}
						goto done
					case "fin", "rst":
						flags := byte(17)
						if kind == "rst" {
							flags = 20
						}
						q := localTCPPacket(flags, nil)
						if err := b.Push(d, st, id, tuple, q, func([]byte) error { return nil }, l, now); err != nil {
							t.Fatal(err)
						}
						goto done
					case "old-generation":
						e.Reload(e.Config())
					}
				}
				raw := localTCPPacket(24, data)
				seq := 100
				if i == 1 {
					seq += cut
				}
				binary.BigEndian.PutUint32(raw[24:], uint32(seq))
				binary.BigEndian.PutUint32(raw[28:], 200)
				if kind == "unsupported" && i == 1 {
					raw[32] = 0x40
				}
				originals = append(originals, append([]byte(nil), raw...))
				origin := i
				err := b.Push(d, st, id, tuple, raw, func(q []byte) error {
					calls++
					if kind == "send-failure" && calls == 2 {
						return errors.New("injected second send")
					}
					// Address context belongs to the original, even after disorder reorders.
					offset := int(int32(binary.BigEndian.Uint32(q[24:]) - 100))
					if offset >= 0 {
						if origin == 0 && offset >= cut || origin == 1 && offset < cut {
							t.Error("wrong original send/address context")
						}
					}
					sent = append(sent, append([]byte(nil), q...))
					return nil
				}, l, now.Add(time.Duration(i)*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 && calls != 0 {
					t.Fatal("partial hello sent before decision")
				}
			}
		done:
			if b.hello.Pending() || b.sends != nil {
				t.Fatal("buffer or send context retained")
			}
			f := l.Snapshot(42).Flows[0]
			if f.Counters.Relayed != 0 || f.Counters.RelayedBytes != 0 {
				t.Fatal("relay evidence")
			}
			if kind == "success" {
				if f.Route != "DIRECT_PLUS" || f.Counters.DirectPlus == 0 || f.Counters.FakeTLS != 1 || f.LocalInspection == nil || f.LocalInspection.Reason != "REASSEMBLY_COMPLETE" || !f.LocalInspection.TransformApplied || f.LocalInspection.ObservedSNI != "www.youtube.com" {
					t.Fatal(f)
				}
				// Later ACK/FIN/cutoff traffic cannot erase the applied decision.
				for _, flags := range []byte{16, 17} {
					if err := b.Push(d, st, id, tuple, localTCPPacket(flags, nil), func([]byte) error { return nil }, l, now); err != nil {
						t.Fatal(err)
					}
				}
				if f = l.Snapshot(42).Flows[0]; f.Route != "DIRECT_PLUS" {
					t.Fatal("ACK reset route")
				}
			} else {
				if f.Route != "DIRECT" || f.Counters.DirectPlus != 0 || f.Counters.FakeTLS != 0 || st.Applied() {
					t.Fatal("failed flow claimed transform", f)
				}
				for _, original := range originals {
					found := false
					for _, q := range sent {
						found = found || bytes.Equal(q, original)
					}
					if !found {
						t.Fatal("original missing on fail-open")
					}
				}
			}
		})
	}
}
