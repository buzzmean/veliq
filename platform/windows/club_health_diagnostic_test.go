package windowsplatform

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPersistentSchannelExactCodeAndProcessGeneration(t *testing.T) {
	now := time.Now().UTC()
	birth := uint64(now.Add(-time.Minute).UnixNano()/100) + 116444736000000000
	raw := []byte(fmt.Sprintf(`<Event><System><Provider Name="Schannel"/><EventID>36876</EventID><EventRecordID>90</EventRecordID><TimeCreated SystemTime="%s"/><Execution ProcessID="999"/></System><EventData><Data Name="ErrorCode">0x80092013</Data><Data Name="CallerProcessId">42</Data><Data Name="CallerProcessImage">C:\Games\r5apex.exe</Data><Data Name="Binary">SECRET_CERTIFICATE_NOT_FOR_UPLOAD</Data></EventData></Event>`, now.Format(time.RFC3339Nano)))
	lookup := func(pid uint32) (ProcessIdentity, error) {
		return ProcessIdentity{PID: pid, Path: `C:\Games\r5apex.exe`, CreationTime: birth}, nil
	}
	e, ok := decodeDiagnosticEvent("System", raw, lookup)
	if !ok || e.NativeCode != 0x80092013 || e.EventID != 36876 || e.PID != 42 || !e.ProcessVerified || e.App != "r5apex.exe" {
		t.Fatalf("%+v", e)
	}
	birth += uint64(2 * time.Minute / 100)
	e, ok = decodeDiagnosticEvent("System", raw, lookup)
	if !ok || e.ProcessVerified || e.Birth != 0 || e.App != "" {
		t.Fatal("PID reuse misattributed")
	}
	raw = []byte(strings.ReplaceAll(string(raw), `<Data Name="CallerProcessId">42</Data>`, ""))
	e, _ = decodeDiagnosticEvent("System", raw, lookup)
	if e.PID != 0 || e.ProcessVerified {
		t.Fatal("LSASS used as caller")
	}
}
