package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
)

func TestPersistentBodyAcceptsMixedLegacyAndClubLinkMetadata(t *testing.T) {
	b := persistentFixtureBatch("PC13")
	legacy := b.Events[0]
	e := legacy
	e.ID = strings.Repeat("c", 32)
	e.At = time.Now().UTC()
	e.Component, e.Observer, e.State, e.Code = "CLUB_LINK", "PASSIVE_TCP_TABLE", "failed", "CONNECTION_LOST"
	e.NativeCode, e.EventID = 0, 0
	e.PID, e.Birth, e.App, e.ProcessVerified = 24, 100, "langameservice.exe", true
	e.Incident = strings.Repeat("d", 32)
	e.ClubLink = clubhealth.ClubLink{Kind: "LANGAME", LinkID: e.Incident, PeerID: strings.Repeat("e", 32), Protocol: "TCP4",
		Event: e.Code, Previous: "ESTABLISHED", Current: "ABSENT", LastEstablishedAt: e.At.Add(-4 * time.Second)}
	b.Events = append(b.Events, e)
	raw, err := json.Marshal(clubhealth.PersistentRequest{Batch: b})
	if err != nil {
		t.Fatal(err)
	}
	var parsed clubhealth.PersistentRequest
	if err = body(httptest.NewRequest("POST", clubhealth.PersistentEndpoint, bytes.NewReader(raw)), &parsed); err != nil || parsed.Batch.Validate(time.Now()) != nil {
		t.Fatal("strict CP parser rejected mixed old/new events", err)
	}
	if parsed.Batch.Events[0] != legacy || parsed.Batch.Events[1] != e || parsed.Batch.Audience() != b.Audience() {
		t.Fatal("CP rewrote old IDs, optional evidence or proof-bound digest")
	}
	// Unknown metadata stays forbidden. Deployment must update the accepting CP
	// before enabling the client producer; no relaxed decoder is introduced.
	bad := bytes.Replace(raw, []byte(`"kind":"LANGAME"`), []byte(`"kind":"LANGAME","raw_message":"forbidden"`), 1)
	if err = body(httptest.NewRequest("POST", clubhealth.PersistentEndpoint, bytes.NewReader(bad)), &parsed); err == nil {
		t.Fatal("unknown nested diagnostic field accepted")
	}
}
