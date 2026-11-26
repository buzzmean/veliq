package clubhealth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/security"
)

func clubLinkFixture(at time.Time) Diagnostic {
	e := diagnosticFixture(100, at)
	e.Component, e.Observer, e.Code = "CLUB_LINK", "PASSIVE_TCP_TABLE", "CONNECTION_LOST"
	e.NativeCode = 0
	e.PID, e.Birth, e.App, e.ProcessVerified = 24, 123456, "langameservice.exe", true
	e.Incident = strings.Repeat("c", 32)
	e.ClubLink = ClubLink{Kind: "LANGAME", LinkID: e.Incident, PeerID: strings.Repeat("d", 32), Protocol: "TCP4",
		Event: e.Code, Previous: "ESTABLISHED", Current: "ABSENT", LastEstablishedAt: at.Add(-4 * time.Second)}
	return e
}

func TestClubLinkValidationRequiresBoundedPositiveEvidence(t *testing.T) {
	at := time.Now().UTC()
	valid := clubLinkFixture(at)
	if !valid.Valid(at) {
		t.Fatal("valid observation rejected")
	}
	for name, change := range map[string]func(*Diagnostic){
		"missing metadata":         func(e *Diagnostic) { e.ClubLink = ClubLink{} },
		"generic component":        func(e *Diagnostic) { e.Component = "NETWORK" },
		"unverified owner":         func(e *Diagnostic) { e.ProcessVerified = false },
		"wrong application":        func(e *Diagnostic) { e.App = "chrome.exe" },
		"missing birth":            func(e *Diagnostic) { e.Birth = 0 },
		"different incident":       func(e *Diagnostic) { e.Incident = e.ID },
		"raw peer":                 func(e *Diagnostic) { e.ClubLink.PeerID = "10.1.1.2:9917" },
		"missing link":             func(e *Diagnostic) { e.ClubLink.LinkID = "" },
		"wrong kind":               func(e *Diagnostic) { e.ClubLink.Kind = "ISCSI" },
		"wrong protocol":           func(e *Diagnostic) { e.ClubLink.Protocol = "UDP" },
		"no baseline":              func(e *Diagnostic) { e.ClubLink.LastEstablishedAt = time.Time{} },
		"future baseline":          func(e *Diagnostic) { e.ClubLink.LastEstablishedAt = at.Add(time.Second) },
		"expired baseline":         func(e *Diagnostic) { e.ClubLink.LastEstablishedAt = at.Add(-Retention - time.Second) },
		"no prior establishment":   func(e *Diagnostic) { e.ClubLink.Previous = "UNKNOWN" },
		"invented state":           func(e *Diagnostic) { e.ClubLink.Current = "FAILED_AUTH" },
		"wrong code":               func(e *Diagnostic) { e.Code = "NETWORK_ERROR" },
		"wrong state":              func(e *Diagnostic) { e.State = "observed" },
		"unrelated native code":    func(e *Diagnostic) { e.NativeCode = 10060 },
		"raw port":                 func(e *Diagnostic) { e.Port = 9917 },
		"windows event conflation": func(e *Diagnostic) { e.EventID = 7031 },
		"mutable repeat":           func(e *Diagnostic) { e.Occurrences, e.LastAt = 1, e.At },
	} {
		t.Run(name, func(t *testing.T) {
			e := valid
			change(&e)
			if e.Valid(at) {
				t.Fatal("invalid observation accepted")
			}
		})
	}
	restored := valid
	restored.ID = strings.Repeat("e", 32)
	restored.Code, restored.State = "CONNECTION_RESTORED", "recovered"
	restored.ClubLink.Event, restored.ClubLink.Previous, restored.ClubLink.Current = restored.Code, "ABSENT", "ESTABLISHED"
	if restored.Valid(at) {
		t.Fatal("old baseline claimed a new positive TCP observation")
	}
	restored.ClubLink.LastEstablishedAt = at
	if !restored.Valid(at) {
		t.Fatal("positive TCP observation rejected")
	}
}

func TestClubLinkComparableRoundTripAndImmutableFacts(t *testing.T) {
	at := time.Now().UTC()
	e := clubLinkFixture(at)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Diagnostic
	if err = security.Parse(raw, &decoded); err != nil || decoded != e {
		t.Fatalf("comparable metadata changed on round trip: %v", err)
	}
	keys := map[Diagnostic]bool{e.RepeatKey(): true}
	if !keys[decoded.RepeatKey()] {
		t.Fatal("value-equivalent metadata split repeat keys")
	}
	if changed, compatible := DiagnosticUpdate(e, decoded); changed || !compatible {
		t.Fatal("same fact conflicted")
	}
	decoded.ClubLink.PeerID = strings.Repeat("f", 32)
	if _, compatible := DiagnosticUpdate(e, decoded); compatible {
		t.Fatal("existing event ID was reassigned to another peer")
	}
	legacy := diagnosticFixture(101, at)
	raw, _ = json.Marshal(legacy)
	if strings.Contains(string(raw), "club_link") {
		t.Fatal("optional value changed old event payload/digest")
	}
	decoded = Diagnostic{}
	if err = security.Parse(raw, &decoded); err != nil || !decoded.Valid(at) {
		t.Fatal("new receiver rejected legacy metadata", err)
	}
	legacy.ClubLink = e.ClubLink
	if legacy.Valid(at) {
		t.Fatal("legacy Windows event was silently reinterpreted as club connectivity")
	}
}
