package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flightrecorder"
)

func TestFlightMutationCorrelationDoesNotRecordArgumentsOrRawErrors(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	d := diagnosticRuntimeFixture()
	c.diagnostics.Store(d)
	c.flight.Store(&flightRecorderRuntime{})
	// Exercise the real dispatcher and its existing parser failure.
	_, err := c.Handle(context.Background(), "settings.set", []byte(`{"unknown":"PRIVATE_REQUEST_BODY"}`))
	if err == nil {
		t.Fatal("invalid settings accepted")
	}
	var began, returned bool
	var incident string
	for len(d.input) > 0 {
		e := (<-d.input).event
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "PRIVATE_REQUEST_BODY") {
			t.Fatal("body in journal")
		}
		if e.Operation != "SETTINGS_SET" {
			continue
		}
		if e.Code == "REQUEST_BEGIN" {
			began = true
			incident = e.Incident
		}
		if e.Code != "REQUEST_BEGIN" {
			returned = true
			if e.Incident != incident {
				t.Fatal("request correlation lost")
			}
		}
	}
	if !began || !returned || c.flightIPCInFlight.Load() != 0 {
		t.Fatal("operation boundaries/counter missing")
	}
	f := c.beginFlightOperation("activation.set")
	f(errors.New("https://secret.example/?code=PRIVATE_ERROR_TOKEN"))
	for len(d.input) > 0 {
		raw, _ := json.Marshal((<-d.input).event)
		if strings.Contains(string(raw), "PRIVATE_ERROR_TOKEN") {
			t.Fatal("raw error logged")
		}
	}
	if c.beginFlightOperation("unknown.PRIVATE_METHOD") != nil || c.beginFlightOperation("status") != nil {
		t.Fatal("untrusted method or periodic read recorded")
	}
}

func TestFlightBusyStateIsUnknownAndDoesNotWaitForControllerLocks(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.mu.Lock()
	c.activation.mu.Lock()
	done := make(chan flightrecorder.RuntimeState, 1)
	go func() { done <- c.flightStateSnapshot() }()
	var s flightrecorder.RuntimeState
	select {
	case s = <-done:
	case <-time.After(time.Second):
		c.activation.mu.Unlock()
		c.mu.Unlock()
		t.Fatal("sampler waited on control lock")
	}
	c.activation.mu.Unlock()
	c.mu.Unlock()
	if s.Known&(flightrecorder.StateCapture|flightrecorder.StateAutomatic|flightrecorder.StateActivation) != 0 {
		t.Fatal("busy state reported known")
	}
	s = c.flightStateSnapshot()
	if s.Known&(flightrecorder.StateCapture|flightrecorder.StateAutomatic|flightrecorder.StateActivation) == 0 {
		t.Fatal("available state omitted")
	}
}

func TestFlightIPCReadIsBoundedAndKeepsClubAndEmergencyGuards(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.clubMode.Store(true)
	if _, err := c.HandleOwnerIPC(context.Background(), "flight.status", nil); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"limit":9}`, `{"limit":-1}`, `{"limit":1000000}`, `{"limit":2,"secret":"PRIVATE"}`} {
		if _, err := c.HandleOwnerIPC(context.Background(), "flight.context", []byte(raw)); err == nil {
			t.Fatal("unbounded or unknown field accepted")
		}
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "settings.set", []byte(`{}`)); err == nil || err.Error() != "CLUB_ADMIN_MANAGED" {
		t.Fatal("mutation guard changed", err)
	}
	c.emergencyStopped.Store(true)
	if _, err := c.HandleOwnerIPC(context.Background(), "flight.status", nil); err == nil || err.Error() != "EMERGENCY_STOP_IN_PROGRESS" {
		t.Fatal("emergency guard changed", err)
	}
}

func TestFlightActivationEarlyFailureIdentifiesPhaseWithoutPrivatePath(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	d := diagnosticRuntimeFixture()
	c.diagnostics.Store(d)
	_, _, err := c.activationAttempt(context.Background(), Manifest{CAFile: filepath.Join(t.TempDir(), "PRIVATE_CERT_PATH")}, activationRecord{})
	if err == nil {
		t.Fatal("untrusted activation allowed")
	}
	if len(d.input) != 2 {
		t.Fatal("wrong phase count", len(d.input))
	}
	e := (<-d.input).event
	if e.Operation != "CA_VALIDATE" || e.Code != "PHASE_ENTERED" || e.Observer != "ACTIVATION_PHASE" {
		t.Fatal("failed phase not recorded", e)
	}
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), "PRIVATE_CERT_PATH") {
		t.Fatal("path leaked")
	}
	result := (<-d.input).event
	if result.Code != "ACTIVATION_TRUST_NOT_CONFIGURED" || result.State != "failed" || result.Operation != "ACTIVATION_ATTEMPT" {
		t.Fatal("attempt failure missing", result)
	}
}
