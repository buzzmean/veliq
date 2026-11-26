package clubhealth

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClubLinkShadowSurvivesMissingTypedMetadataWithoutChangingWire(t *testing.T) {
	at := time.Date(2026, 11, 26, 8, 0, 0, 123456789, time.UTC)
	for _, protocol := range []string{"TCP4", "TCP6"} {
		for _, event := range []string{"CONNECTION_LOST", "CONNECTION_RESTORED"} {
			t.Run(protocol+"/"+event, func(t *testing.T) {
				e := clubLinkFixture(at)
				e.ClubLink.Protocol = protocol
				if event == "CONNECTION_RESTORED" {
					e.Code, e.State = event, "recovered"
					e.ClubLink.Event, e.ClubLink.Previous, e.ClubLink.Current = event, "ABSENT", "ESTABLISHED"
					e.ClubLink.LastEstablishedAt = at
				}
				both, ok := e.WithClubLinkShadow()
				if !ok || !both.Valid(at) || len(both.Operation) != 58 || !symbol.MatchString(both.Operation) || e.Operation != "" {
					t.Fatal("producer failed old allowlist or mutated its input")
				}
				downlevel := both
				downlevel.ClubLink = ClubLink{}
				for _, wire := range []Diagnostic{e, both, downlevel} {
					before, _ := json.Marshal(wire)
					batch := Batch{Protocol: 1, Events: []Diagnostic{wire}}
					digest := batch.Audience()
					link, valid := wire.EffectiveClubLink()
					canonical, canonicalOK := wire.CanonicalClubLink()
					after, _ := json.Marshal(wire)
					if !valid || !canonicalOK || !wire.Valid(at) || !sameClubLink(link, e.ClubLink) || canonical != e {
						t.Fatal("representations do not recover the same exact fact")
					}
					if string(before) != string(after) || batch.Audience() != digest {
						t.Fatal("decoding changed signed wire bytes")
					}
					if wire.Operation != "" && (Batch{Protocol: 1, Events: []Diagnostic{canonical}}).Audience() == digest {
						t.Fatal("storage projection was mistaken for the wire digest")
					}
				}
			})
		}
	}
}

func TestClubLinkShadowRejectsMalformedOrContradictoryEvidence(t *testing.T) {
	at := time.Date(2026, 11, 26, 8, 0, 0, 123456789, time.UTC)
	base, ok := clubLinkFixture(at).WithClubLinkShadow()
	if !ok {
		t.Fatal("fixture")
	}
	parts := strings.Split(base.Operation, "_")
	for _, operation := range []string{
		"CL1", "CL1_", "CL2_4_" + parts[2] + "_" + parts[3],
		"CL1_5_" + parts[2] + "_" + parts[3], "CL1_04_" + parts[2] + "_" + parts[3],
		"CL1_4_" + strings.ToLower(parts[2]) + "_" + parts[3],
		"CL1_4_" + strings.Repeat("Z", 32) + "_" + parts[3],
		"CL1_4_" + parts[2] + "_0", "CL1_4_" + parts[2] + "_01",
		"CL1_4_" + parts[2] + "_+1", "CL1_4_" + parts[2] + "_-1",
		"CL1_4_" + parts[2] + "_9223372036854775808",
		"CL1_4_" + parts[2] + "_" + strconv.FormatInt(at.Add(time.Second).UnixNano(), 10),
		"CL1_4_" + parts[2] + "_" + strconv.FormatInt(at.Add(-Retention-time.Second).UnixNano(), 10),
		base.Operation + "_EXTRA", strings.Repeat("A", 65), "WINHTTP_SEND_REQUEST",
	} {
		t.Run(operation, func(t *testing.T) {
			e := base
			e.Operation, e.ClubLink = operation, ClubLink{}
			if _, valid := e.EffectiveClubLink(); valid || e.Valid(at) {
				t.Fatal("invalid envelope supplied a club transition")
			}
		})
	}
	for name, change := range map[string]func(*Diagnostic){
		"different typed peer":       func(e *Diagnostic) { e.ClubLink.PeerID = strings.Repeat("f", 32) },
		"different typed protocol":   func(e *Diagnostic) { e.ClubLink.Protocol = "TCP6" },
		"different typed baseline":   func(e *Diagnostic) { e.ClubLink.LastEstablishedAt = e.At },
		"different typed incident":   func(e *Diagnostic) { e.ClubLink.LinkID = strings.Repeat("f", 32) },
		"different typed event":      func(e *Diagnostic) { e.ClubLink.Event = "CONNECTION_RESTORED" },
		"foreign component":          func(e *Diagnostic) { e.Component = "NETWORK" },
		"missing ID":                 func(e *Diagnostic) { e.ID = "" },
		"missing session":            func(e *Diagnostic) { e.Session = "" },
		"missing service provenance": func(e *Diagnostic) { e.ServicePID = 0 },
		"missing incident":           func(e *Diagnostic) { e.Incident = "" },
		"missing owner":              func(e *Diagnostic) { e.ProcessVerified = false },
		"wrong owner":                func(e *Diagnostic) { e.App = "chrome.exe" },
		"wrong observer":             func(e *Diagnostic) { e.Observer = "WINDOWS_EVENT_LOG" },
		"wrong state":                func(e *Diagnostic) { e.State = "observed" },
		"repeat metadata":            func(e *Diagnostic) { e.LastAt = at },
		"native code overload":       func(e *Diagnostic) { e.NativeCode = 123 },
		"record ID overload":         func(e *Diagnostic) { e.RecordID = 123 },
	} {
		t.Run(name, func(t *testing.T) {
			e := base
			change(&e)
			if _, valid := e.EffectiveClubLink(); valid || e.Valid(at) {
				t.Fatal("contradictory or unproven metadata accepted")
			}
		})
	}
	legacy := diagnosticFixture(120, at)
	legacy.Operation = "WINHTTP_SEND_REQUEST"
	if canonical, valid := legacy.CanonicalClubLink(); !valid || canonical != legacy {
		t.Fatal("ordinary legacy diagnostic changed")
	}
	legacy.Operation = base.Operation
	if legacy.Valid(at) {
		t.Fatal("envelope silently changed an unrelated event's meaning")
	}
}

func TestClubLinkShadowComparesInstantsAndRefusesUnixNanoOverflow(t *testing.T) {
	at := time.Date(2026, 11, 26, 8, 0, 0, 123456789, time.UTC)
	e, _ := clubLinkFixture(at).WithClubLinkShadow()
	e.ClubLink.LastEstablishedAt = e.ClubLink.LastEstablishedAt.In(time.FixedZone("fixture", 3*60*60))
	canonical, ok := e.CanonicalClubLink()
	if !ok || canonical.ClubLink.LastEstablishedAt.Location() != time.UTC {
		t.Fatal("same instant conflicted or storage kept location-dependent representation")
	}
	e = clubLinkFixture(time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC))
	if _, ok := e.WithClubLinkShadow(); ok {
		t.Fatal("UnixNano wrapped an unrepresentable instant")
	}
}
