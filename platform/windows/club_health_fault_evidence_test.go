package windowsplatform

import (
	"fmt"
	"strings"
	"testing"
)

func faultEvent(provider string, code int, data string) []byte {
	return []byte(fmt.Sprintf(`<Event><System><Provider Name="%s"/><EventID>%d</EventID><Level>2</Level><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-11-27T10:43:34.1234567Z"/></System><EventData>%s</EventData></Event>`, provider, code, data))
}

func TestLangameFaultRequiresStructuredFaultingImage(t *testing.T) {
	for _, tc := range []struct {
		name, provider        string
		code                  int
		data, want, operation string
		accepted              bool
	}{
		{"queued WER is a report", "Windows Error Reporting", 1001, `<Data Name="EventName">APPCRASH</Data><Data Name="P1">LanGameService.exe</Data>`, "APPLICATION_REPORT", "", true},
		{"hang is not crash", "Application Hang", 1002, `<Data Name="AppName">LanGameService.exe</Data>`, "APPLICATION_REPORT", "", true},
		{"unrelated WER mention", "Windows Error Reporting", 1001, `<Data Name="P1">other.exe</Data><Data Name="Description">calls LanGameService.exe</Data>`, "", "", false},
		{"fault module mention", "Application Error", 1000, `<Data Name="AppName">other.exe</Data><Data Name="ModuleName">LanGameService.exe</Data>`, "", "", false},
		{"structured actual fault", "Application Error", 1000, `<Data Name="AppName">C:\LanGame\LanGameService.exe</Data><Data Name="ExceptionCode">0xc0000005</Data>`, "LANGAME_CRASH", "APPLICATION_FAULT", true},
		{"service stopped normally", "Service Control Manager", 7036, `<Data Name="param1">LanGameService</Data>`, "", "", false},
		{"service error not termination", "Service Control Manager", 7023, `<Data Name="param1">LanGameService</Data>`, "", "", false},
		{"unexpected termination", "Service Control Manager", 7031, `<Data Name="param1">LanGameService</Data>`, "LANGAME_CRASH", "SERVICE_TERMINATION", true},
		{"unexpected termination no action", "Service Control Manager", 7034, `<Data Name="param1">LanGameService</Data>`, "LANGAME_CRASH", "SERVICE_TERMINATION", true},
		{"startup failure", "Service Control Manager", 7000, `<Data Name="param1">LanGameService</Data>`, "LANGAME_START_FAILED", "SERVICE_START_FAILURE", true},
		{"provider warning is only observation", "LanGame", 10, `<Data>no crash</Data>`, "LANGAME_ERROR", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			channel := "Application"
			if tc.provider == "Service Control Manager" {
				channel = "System"
			}
			e, ok := decodeDiagnosticEvent(channel, faultEvent(tc.provider, tc.code, tc.data), nil)
			if ok != tc.accepted || ok && (e.Code != tc.want || e.Operation != tc.operation) {
				t.Fatalf("accepted=%v event=%+v", ok, e)
			}
			if tc.want == "APPLICATION_REPORT" && (e.Component == "LANGAME" || strings.Contains(e.Code, "CRASH")) {
				t.Fatal("report promoted to live crash")
			}
		})
	}
}

func TestWindowsFaultIdentitySurvivesRepeatAndSeparatesLogGeneration(t *testing.T) {
	raw := faultEvent("Application Error", 1000, `<Data Name="AppName">LanGameService.exe</Data>`)
	a, ok := decodeDiagnosticEvent("Application", raw, nil)
	if !ok {
		t.Fatal("missing fault")
	}
	b, _ := decodeDiagnosticEvent("Application", raw, nil)
	if a.ID != b.ID {
		t.Fatal("unstable identity")
	}
	next := []byte(strings.Replace(string(raw), "10:43:34.1234567Z", "10:44:34.1234567Z", 1))
	b, _ = decodeDiagnosticEvent("Application", next, nil)
	if a.ID == b.ID {
		t.Fatal("reused record number merged across log generation")
	}
	if _, ok = decodeDiagnosticEvent("System", raw, nil); ok {
		t.Fatal("Application Error accepted from wrong channel")
	}
	if _, ok = decodeDiagnosticEvent("Application", faultEvent("Service Control Manager", 7031, `<Data Name="param1">LanGameService</Data>`), nil); ok {
		t.Fatal("SCM termination accepted from wrong channel")
	}
}
