package clientservice

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/gameudp"
)

func preferenceFixture() (*gameudp.Engine, gameudp.Key) {
	const image = `D:\Steam\game\bin\cs2.exe`
	k := gameudp.Key{Network: strings.Repeat("a", 64), Application: image, PID: 100, Birth: 123,
		Source: netip.MustParseAddrPort("192.0.2.4:55000"), Destination: netip.MustParseAddrPort("203.0.113.10:27015")}
	e := gameudp.NewLadder(nil)
	e.SetCS2Auto(true)
	e.Configure(image, true)
	e.SetNetwork(k.Network)
	e.SetReason("")
	return e, k
}

func TestCS2PreferenceSidecarRestoresOnlyConfirmedPath(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "game-udp.json")
	if err := os.WriteFile(legacy, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	e, k := preferenceFixture()
	now := time.Now().UTC()
	var disk cs2DiskState
	f, err := e.OpenCS2(k, now)
	if err != nil {
		t.Fatal(err)
	}
	e.CS2LocalFailure(f, now)
	if status := disk.sync(dir, k.Application, e, now); status != "" {
		t.Fatal(status)
	}
	if _, err = os.Stat(disk.path); !os.IsNotExist(err) {
		t.Fatal("failed attempt written", err)
	}
	k.Source = netip.MustParseAddrPort("192.0.2.4:55001")
	now = now.Add(time.Second)
	f, err = e.OpenCS2(k, now)
	if err != nil || e.Evidence(f).Stage != gameudp.LocalSocket {
		t.Fatal(err, e.Evidence(f))
	}
	e.Outgoing(f, 20, now)
	e.Reply(f, 22, now)
	flow := e.Evidence(f)
	err = e.RecordCS2Outcome(gameudp.CS2Outcome{FlowID: flow.ID, Started: flow.Started, PID: k.PID, Birth: k.Birth, Destination: k.Destination, Outcome: "JOINED", Phase: "INGAME"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if status := disk.sync(dir, k.Application, e, now); status != "" {
		t.Fatal(status)
	}
	raw, err := os.ReadFile(disk.path)
	if err != nil {
		t.Fatal(err)
	}
	var file cs2PreferenceFile
	if err = json.Unmarshal(raw, &file); err != nil || len(file.Routes) != 1 || file.Routes[0].Stage != gameudp.LocalSocket {
		t.Fatal(file, err)
	}
	if strings.Contains(string(raw), "pid") || strings.Contains(string(raw), "flow_id") || strings.Contains(string(raw), "source") {
		t.Fatalf("persisted live details:%s", raw)
	}
	other, _ := os.ReadFile(legacy)
	if string(other) != "untouched" {
		t.Fatal("changed 715 profile")
	}
	next, k := preferenceFixture()
	var nextDisk cs2DiskState
	if status := nextDisk.sync(dir, k.Application, next, now); status != "" {
		t.Fatal(status)
	}
	if got := next.Snapshot(); len(got.Flows) != 0 || len(got.CS2Endpoints) != 0 {
		t.Fatal("restored a live join observation")
	}
	f, err = next.OpenCS2(k, now)
	if err != nil || next.Evidence(f).Stage != gameudp.LocalSocket {
		t.Fatal(next.Evidence(f), err)
	}
	next.CS2LocalFailure(f, now)
	if status := nextDisk.sync(dir, k.Application, next, now); status != "" {
		t.Fatal(status)
	}
	again, k := preferenceFixture()
	var empty cs2DiskState
	if status := empty.sync(dir, k.Application, again, now); status != "" {
		t.Fatal(status)
	}
	f, err = again.OpenCS2(k, now)
	if err != nil || again.Evidence(f).Stage != gameudp.Direct {
		t.Fatal("removed preference came back", err)
	}
}

func TestCS2PreferenceCorruptionNeverGrantsARoute(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	e, k := preferenceFixture()
	var disk cs2DiskState
	disk.sync(dir, k.Application, e, now)
	file := cs2PreferenceFile{Version: 1, Application: gameudp.Canonical(k.Application), Routes: []gameudp.CS2Preference{
		{Network: k.Network, Destination: k.Destination, Stage: gameudp.LocalSocket, ConfirmedAt: now},
		{Network: k.Network, Destination: netip.MustParseAddrPort("203.0.113.11:27015"), Stage: gameudp.Relay, ConfirmedAt: now},
	}}
	raw, _ := json.Marshal(file)
	if err := os.WriteFile(disk.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var load cs2DiskState
	if status := load.sync(dir, k.Application, e, now); status != "CS2_PREFERENCE_READ_FAILED" {
		t.Fatal(status)
	}
	f, err := e.OpenCS2(k, now)
	if err != nil || e.Evidence(f).Stage != gameudp.Direct {
		t.Fatal(err, e.Evidence(f))
	}
	file.Application = "d:/another/cs2.exe"
	file.Routes = file.Routes[:1]
	raw, _ = json.Marshal(file)
	if err := os.WriteFile(disk.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var changed cs2DiskState
	if status := changed.sync(dir, k.Application, e, now); status != "CS2_PREFERENCE_READ_FAILED" {
		t.Fatal(status)
	}
}
