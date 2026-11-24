package clientservice

import (
	"context"
	"net/netip"
	"testing"

	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestClubStorageRemainsDirectEvenWithApplicationRelayProfile(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.enabled = true
	p := profiles.Profile{ID: "storage-test", Name: "Storage fixture", Executables: []string{`C:\Apps\storage.exe`}, Mode: profiles.Manual, RelayID: "VPS-01"}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	c.syncPolicies()
	id := wp.ProcessIdentity{PID: 123, CreationTime: 1, Path: `C:\Apps\storage.exe`}
	tuple := wp.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.168.88.10:50000"), Destination: netip.MustParseAddrPort("192.168.88.252:3260")}
	if d := c.Classify(id, tuple); !d.Route.Direct() || d.Deferred || d.Block {
		t.Fatal("storage intercepted", d)
	}
	tuple.Destination = netip.MustParseAddrPort("8.8.8.8:3260")
	if d := c.Classify(id, tuple); d.Route.Direct() {
		t.Fatal("public peer incorrectly exempted", d)
	}
	tuple.Source = netip.MustParseAddrPort("192.168.88.10:3260")
	tuple.Destination = netip.MustParseAddrPort("8.8.8.8:443")
	if d := c.Classify(id, tuple); d.Route.Direct() {
		t.Fatal("client binding source port 3260 bypassed policy", d)
	}
}
