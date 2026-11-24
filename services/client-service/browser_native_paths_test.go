package clientservice

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/buzzmean/veliq/core/browserproxy"
)

func TestNativeOnlyProofNeverCountsPACDelegationOrOneWayBytes(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	n := &c.browser.native
	n.activate("chrome", false)
	add := func(ingress string) uint64 {
		id, err := n.begin(browserproxy.Request{Ingress: ingress, Owner: browserproxy.Owner{Profile: "chrome"}}, policyTuple("tcp", 443))
		if err != nil {
			t.Fatal(err)
		}
		n.opened(id, browserproxy.Plan{}, nil)
		return id
	}
	pac := add("PAC_NATIVE_UPSTREAM")
	n.bytes(pac, 10, 20)
	n.closed(pac)
	snap := c.nativeSnapshot()
	if snap.NativeOnlyState != "NATIVE_ONLY_NOT_OBSERVED" || snap.NativeOnly.Exchanges != 0 || snap.PACUpstream.Exchanges != 1 || snap.PACUpstream.Active != 0 {
		t.Fatal("PAC manufactured native-only evidence", snap)
	}
	native := add("NATIVE_TCP")
	n.bytes(native, 3, 0)
	if c.nativeSnapshot().NativeOnlyState != "NATIVE_ONLY_NOT_OBSERVED" {
		t.Fatal("one-way bytes claimed native-only proof")
	}
	n.bytes(native, 0, 5)
	n.bytes(native, 7, 9)
	n.closed(native)
	n.closed(native)
	snap = c.nativeSnapshot()
	if snap.NativeOnlyState != "NATIVE_ONLY_OBSERVED" || snap.NativeOnly.Accepted != 1 || snap.NativeOnly.Opened != 1 || snap.NativeOnly.Exchanges != 1 || snap.NativeOnly.Active != 0 || snap.NativeOnly.Sent != 10 || snap.NativeOnly.Received != 14 || snap.PACUpstream.Sent != 10 {
		t.Fatal(snap)
	}
	p := snap.Profiles[0]
	if p.NativeOnly.FirstOpenMS < 0 || p.NativeOnly.FirstExchangeMS < 0 || p.NativeOnly.FirstExchange.IsZero() {
		t.Fatal("actual ingress timing missing", p)
	}
	unknown := add("")
	n.bytes(unknown, 99, 99)
	n.closed(unknown)
	if c.nativeSnapshot().NativeOnly.Exchanges != 1 {
		t.Fatal("unknown legacy ingress inferred as native-only")
	}
	n.activate("chrome", true)
	n.bytes(native, 50, 50)
	if c.nativeSnapshot().NativeOnlyState != "NATIVE_ONLY_NOT_OBSERVED" || c.nativeSnapshot().NativeOnly.Sent != 0 {
		t.Fatal("old activation leaked into new ingress proof")
	}
}
func TestNativeOnlyCountersSurviveRecordEvictionAndIPCIsBounded(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	n := &c.browser.native
	n.activate("edge", false)
	for i := 0; i < 530; i++ {
		kind := "PAC_NATIVE_UPSTREAM"
		if i == 0 {
			kind = "NATIVE_TCP"
		}
		id, err := n.begin(browserproxy.Request{Ingress: kind, Owner: browserproxy.Owner{Profile: "edge"}}, policyTuple("tcp", 443))
		if err != nil {
			t.Fatal(err)
		}
		n.opened(id, browserproxy.Plan{}, nil)
		n.bytes(id, 1, 2)
		n.closed(id)
	}
	s := c.nativeSnapshot()
	raw, _ := json.Marshal(s)
	if s.NativeOnlyState != "NATIVE_ONLY_OBSERVED" || s.NativeOnly.Exchanges != 1 || s.PACUpstream.Exchanges != 529 || len(raw) > 60*1024 || !s.Truncated || s.Lost == 0 {
		t.Fatal("proof lost or unbounded", len(raw), s.NativeOnly, s.PACUpstream)
	}
	for _, r := range s.Records {
		if r.Ingress == "NATIVE_TCP" {
			t.Fatal("test did not evict original native record")
		}
	}
}
