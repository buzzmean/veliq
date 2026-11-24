package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

type hotBackendFixture struct {
	ready, fail bool
	classified  wp.Decision
	id          wp.ProcessIdentity
	tuple       wp.Tuple
	calls       []string
	epoch       uint64
}

func (b *hotBackendFixture) Start(_ context.Context, c wp.Classifier) error {
	b.classified = c(b.id, b.tuple)
	if b.fail {
		return errors.New("driver failed")
	}
	b.ready = true
	return nil
}
func (b *hotBackendFixture) Stop() error { b.ready = false; return nil }
func (b *hotBackendFixture) Status() wp.CaptureStatus {
	return wp.CaptureStatus{Ready: b.ready, Capabilities: wp.Capabilities{TCP: true, UDP: true, IPv4: true}}
}
func (b *hotBackendFixture) Reconfigure(app string, fn func() error) error {
	b.calls = append(b.calls, app)
	return fn()
}
func (b *hotBackendFixture) RequestHotAttach(string) { b.epoch++ }
func (b *hotBackendFixture) HotAttachStatus() wp.HotAttachStatus {
	return wp.HotAttachStatus{Epoch: b.epoch, State: "HOT_ATTACH_RECONNECTING"}
}
func TestHotAttachActivationIsClassifiedBeforeCaptureStarts(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	p := profiles.Profile{ID: "hot", Name: "already running", Executables: []string{`C:\Apps\ChatGPT.exe`}, Mode: profiles.Manual, RelayID: "VPS-01", Fallback: flowpolicy.Required, Custom: true}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	id := wp.ProcessIdentity{PID: 42, CreationTime: 5, Path: p.Executables[0]}
	tuple := wp.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	backend := &hotBackendFixture{id: id, tuple: tuple}
	c.Backend = backend
	for i := 0; i < 2; i++ {
		if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err != nil {
			t.Fatal(err)
		}
		if backend.classified.Route.RelayID != "VPS-01" || !backend.classified.BlockOnFailure || backend.classified.Revision == "" {
			t.Fatal("activation race/direct bypass", backend.classified)
		}
		if c.Snapshot().HotAttach == nil || c.Snapshot().HotAttach.Epoch != uint64(i+1) {
			t.Fatal("missing HOT_ATTACH status")
		}
		if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); err != nil {
			t.Fatal(err)
		}
	}
	backend.fail = true
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err == nil {
		t.Fatal("start failure ignored")
	}
	if c.enabled || c.Snapshot().Optimizing {
		t.Fatal("failed activation advertised")
	}
	p.Mode = profiles.DirectPlus
	p.Fallback = ""
	p.RelayID = ""
	raw, _ := json.Marshal(p)
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	if len(backend.calls) != 1 || backend.calls[0] != "hot" {
		t.Fatal("profile update not scoped", backend.calls)
	}
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	if len(backend.calls) != 1 {
		t.Fatal("idempotent profile reset active flows")
	}
}
