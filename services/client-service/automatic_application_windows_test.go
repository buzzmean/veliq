//go:build windows

package clientservice

import (
	"context"
	"os"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestAutomaticNativeOwnerRevalidatedBeforeAnySocket(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled, c.selfExecutable = true, "different-service.exe"
	id, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := discoveredApplication(id)
	if !ok {
		t.Fatal("test process identity missing", id)
	}
	owner := browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}
	if _, err := c.automaticOwnerProfile(owner); err != nil {
		t.Fatal(err)
	}
	stale := owner
	stale.Birth++
	if _, err := c.automaticOwnerProfile(stale); err == nil {
		t.Fatal("stale PID accepted")
	}
	tuple := destTuple("tcp", "93.184.216.34", 443)
	d := wp.ResolveDeferredDecision(c.Classify(id, tuple), "ordinary.example.org", "REASSEMBLY_COMPLETE")
	if d.OpenDeferred == nil {
		t.Fatal("not captured")
	}
	p.Mode, p.Custom = profiles.Direct, true
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	conn, _, err := d.OpenDeferred(context.Background(), d, "REASSEMBLY_COMPLETE")
	if conn != nil || err == nil {
		t.Fatal("queued old policy opened after DIRECT override", err)
	}
}
