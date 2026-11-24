package windowsplatform

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClubHealthWindowsEventKeepsOnlyFaultMetadata(t *testing.T) {
	eventXML := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
		<Provider Name="User32"/><EventID>1074</EventID><Level>4</Level>
		<TimeCreated SystemTime="2026-11-23T01:00:04.0559229Z"/><EventRecordID>4242</EventRecordID>
		</System><EventData><Data Name="param1">C:\Users\private-account\wmiprvse.exe (PRIVATE-PC)</Data>
		<Data Name="param2">192.168.2.3</Data></EventData></Event>`
	first, ok := decodeClubHealthEvent("System", []byte(eventXML))
	if !ok || first.Kind != "shutdown_requested" || first.Code != 1074 || first.App != "wmiprvse.exe" ||
		!first.Valid(time.Date(2026, 11, 23, 1, 0, 10, 0, time.UTC)) {
		t.Fatal(first, ok)
	}
	second, _ := decodeClubHealthEvent("System", []byte(eventXML))
	if first.ID != second.ID {
		t.Fatal("duplicate rendered event did not reuse identity")
	}
	b, _ := json.Marshal(first)
	for _, private := range []string{"private-account", "192.168", "PRIVATE-PC"} {
		if strings.Contains(string(b), private) {
			t.Fatal("raw event metadata escaped")
		}
	}
	if _, ok := decodeClubHealthEvent("System", []byte(strings.Replace(eventXML, "User32", "UnexpectedProvider", 1))); ok {
		t.Fatal("unexpected provider accepted")
	}
}
