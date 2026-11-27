package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/flightrecorder"
	"github.com/buzzmean/veliq/core/security"
)

// This compiles the unchanged official762 journal/signer and performs its real
// HTTP upload. The strict ingestion/ACK contract is the existing CP806 path.
func TestFlightRecorderActual762JournalSignedDeliveryACKAndReplay(t *testing.T) {
	if os.Getenv("VELIQ_TEST_DOWNLEVEL_762") != "1" {
		t.Skip("set VELIQ_TEST_DOWNLEVEL_762=1 with exact762 source and isolated PostgreSQL")
	}
	if os.Getenv("VELIQ_TEST_DATABASE_URL") == "" {
		t.Fatal("isolated PostgreSQL required for actual762 acceptance")
	}
	binary := buildDownlevel762Codec(t)
	cases := map[string]flightrecorder.Summary{
		"known_context":     {Flags: flightrecorder.KnownCPU | flightrecorder.KnownWorkingSet | flightrecorder.KnownIO | flightrecorder.KnownGC | flightrecorder.KnownInterval | flightrecorder.VerifiedProcess | flightrecorder.ContextPre, SpanMS: 5000, CPUTimeUS: 20000, WorkingSetKiB: 51200, ReadKiB: 2, WriteKiB: 1, GCPauseUS: 55},
		"unknown":           {Flags: flightrecorder.Heartbeat},
		"reset":             {Flags: flightrecorder.CounterReset | flightrecorder.Heartbeat},
		"saturated_context": {Flags: flightrecorder.KnownCPU | flightrecorder.KnownWorkingSet | flightrecorder.KnownInterval | flightrecorder.Saturated | flightrecorder.ContextPost, SpanMS: 5000, CPUTimeUS: 1<<32 - 1, WorkingSetKiB: 1<<32 - 1},
	}
	for name, summary := range cases {
		t.Run(name, func(t *testing.T) {
			api, store, _ := accountAPI(t, true)
			_, device, key := persistentDeviceFixture(t, store, "PC13")
			event := persistentFixtureBatch("PC13").Events[0]
			event.Component, event.Observer, event.State, event.Code, event.NativeCode = "PERFORMANCE", "FLIGHT_RECORDER", "observed", "RESOURCE_CONTEXT", 0
			event.Operation = summary.Encode()
			event.Incident = event.ID
			if summary.Flags&flightrecorder.VerifiedProcess != 0 {
				event.PID, event.Birth, event.App, event.ProcessVerified = 42, 1234, "veliq-service.exe", true
			}
			if _, ok := flightrecorder.Decode(event.Operation); !ok {
				t.Fatal("invalid canonical fixture")
			}
			acked := persistentFixtureBatch("PC13").Events[0]
			journal := clubhealth.Journal{Format: 1, Device: device, Open: true, Lost: 714991, Rows: []clubhealth.JournalRow{{Event: event}, {Event: acked, Acked: true}}}
			rawJournal, _ := json.Marshal(journal)
			server := httptest.NewServer(api.Handler())
			defer server.Close()
			input, _ := json.Marshal(struct {
				Journal  json.RawMessage
				Device   string
				Seed     []byte
				URL      string
				Now      time.Time
				Reporter clubhealth.Reporter
			}{rawJournal, device, key.Seed(), server.URL + clubhealth.PersistentEndpoint, event.At, clubhealth.Reporter{PC: "PC13", Version: "0.3.762", Source: "0faa9aab", Session: strings.Repeat("a", 32), ServicePID: 762}})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary)
			cmd.Stdin = bytes.NewReader(input)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("actual762 cold codec/signer/upload: %v %s", err, &stderr)
			}
			var result struct {
				Before  clubhealth.Journal
				After   clubhealth.Journal
				Request clubhealth.PersistentRequest
				Receipt clubhealth.Receipt
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Before.Lost != 714991 || result.After.Lost != 714991 || len(result.Before.Rows) != 2 || len(result.After.Rows) != 2 || result.Before.Rows[0].Event != event || result.After.Rows[0].Event != event || result.Before.Rows[0].Acked || !result.After.Rows[0].Acked || !result.After.Rows[1].Acked {
				t.Fatal("actual762 changed immutable bytes/ID/ACK/loss")
			}
			if len(result.Request.Batch.Events) != 1 || result.Request.Batch.Events[0] != event || !result.Receipt.Accepts(result.Request.Batch) {
				t.Fatal("original signed wire/digest not preserved")
			}
			pub, err := security.DecodePublicKey(mustDeviceKey(t, store, device))
			if err != nil || result.Request.Proof.Verify(pub, time.Now()) != nil {
				t.Fatal("not an actual762 signed proof")
			}
			for i := 0; i < 2; i++ {
				proof, _ := security.NewProof(device, result.Request.Batch.Audience(), key, time.Now())
				if status, receipt := diagnosticRequest(t, api, clubhealth.PersistentRequest{Batch: result.Request.Batch, Proof: proof}); status != 200 || !receipt.Accepts(result.Request.Batch) {
					t.Fatal("immutable replay failed", status)
				}
			}
			var count int
			var raw []byte
			if err := store.DB.QueryRow(context.Background(), "SELECT count(*) FROM club_health_persistent_events WHERE device_id=$1", device).Scan(&count); err != nil || count != 1 {
				t.Fatal("duplicate stored rows", count, err)
			}
			if err := store.DB.QueryRow(context.Background(), "SELECT summary FROM club_health_persistent_events WHERE device_id=$1 AND event_id=$2", device, event.ID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var stored clubhealth.Diagnostic
			if json.Unmarshal(raw, &stored) != nil || stored != event {
				t.Fatal("stored metadata was rewritten")
			}
			bad := event
			bad.NativeCode = 1
			batch := clubhealth.Batch{Protocol: 1, Events: []clubhealth.Diagnostic{bad}}
			proof, _ := security.NewProof(device, batch.Audience(), key, time.Now())
			if status, _ := diagnosticRequest(t, api, clubhealth.PersistentRequest{Batch: batch, Proof: proof}); status != 409 {
				t.Fatal("strict sameID collision guard weakened", status)
			}
		})
	}
}
