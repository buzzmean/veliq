package windowsplatform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
)

// The old812 diagnostic/journal codec has no new fields. The same record is
// decoded again after upgrade, without changing its original bytes or cold ACK.
func TestOld812WindowsJournalReplayRetainsAuditAndACK(t *testing.T) {
	for _, tc := range []struct {
		provider string
		code     int
		data     string
	}{
		{"Windows Error Reporting", 1001, `<Data Name="P1">LanGameService.exe</Data>`},
		{"Application Error", 1000, `<Data Name="AppName">LanGameService.exe</Data>`},
		{"Application Hang", 1002, `<Data Name="AppName">LanGameService.exe</Data>`},
		{"Service Control Manager", 7034, `<Data Name="param1">LanGameService</Data>`},
		{"Service Control Manager", 7031, `<Data Name="param1">LanGameService</Data>`},
		{"Service Control Manager", 7000, `<Data Name="param1">LanGameService</Data>`},
	} {
		t.Run(fmt.Sprintf("%s_%d", tc.provider, tc.code), func(t *testing.T) {
			channel := "Application"
			if tc.provider == "Service Control Manager" {
				channel = "System"
			}
			next, ok := decodeDiagnosticEvent(channel, faultEvent(tc.provider, tc.code, tc.data), nil)
			if !ok {
				t.Fatal("not decoded")
			}
			next.PC, next.Version, next.Source, next.Session, next.ServicePID = "PC08", "0.3.814", "new", strings.Repeat("b", 32), 20
			old := next
			physical := channel + ":" + strconv.FormatUint(next.RecordID, 10) + ":" + next.At.UTC().Format(time.RFC3339Nano)
			sum := sha256.Sum256([]byte(physical))
			old.ID = hex.EncodeToString(sum[:16])
			old.Version, old.Source, old.Session, old.ServicePID = "0.3.812", "old", strings.Repeat("a", 32), 10
			old.Component, old.Code, old.Operation = "LANGAME", "LANGAME_CRASH", ""
			if tc.code == 7000 {
				old.Code = "LANGAME_START_FAILED"
			}
			now := next.At.Add(time.Minute)
			for _, acked := range []bool{false, true} {
				for _, history := range []bool{false, true} {
					// Round-trip bytes using precisely the old shape (new decoder fields are
					// existing old812 fields); do not synthesize an updated journal entry.
					original := clubhealth.Journal{Format: 1, Device: "fixture-device", Rows: []clubhealth.JournalRow{{Event: old, Acked: acked}}, Lost: 7}
					if history {
						original.History, original.Rows = original.Rows, nil
					}
					raw, err := json.Marshal(original)
					if err != nil {
						t.Fatal(err)
					}
					if dir := os.Getenv("BT04_OLD_CODEC_FIXTURE_DIR"); dir != "" {
						raw, err = os.ReadFile(filepath.Join(dir, fmt.Sprintf("%d-%t-%t.json", tc.code, acked, history)))
						if err != nil {
							t.Fatal(err)
						}
						freshRaw, _ := json.Marshal(next)
						if err = os.WriteFile(filepath.Join(dir, fmt.Sprintf("new-%d.json", tc.code)), freshRaw, 0600); err != nil {
							t.Fatal(err)
						}
					}
					path := filepath.Join(t.TempDir(), "old812-journal.json")
					if err = os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					journal := clubhealth.LoadJournal(path, "fixture-device", now)
					if !journal.Add(next, now) || journal.Lost != 7 || len(journal.Rows)+len(journal.History) != 2 || oldAudit(journal, history).Event != old || oldAudit(journal, history).Acked != acked || journal.Rows[len(journal.Rows)-1].Event != next {
						t.Fatalf("old audit changed/lost: %+v", journal)
					}
					{
						b := journal.Batch()
						receipt := clubhealth.Receipt{Protocol: 1, Committed: true, Digest: b.Audience()}
						if !journal.Ack(b, receipt) {
							t.Fatal("old exact batch ACK rejected")
						}
					}
					if err = journal.Save(func(b []byte) error { return os.WriteFile(path, b, 0600) }); err != nil {
						t.Fatal(err)
					}
					journal = clubhealth.LoadJournal(path, "fixture-device", now)
					if journal.Add(next, now) || journal.Lost != 7 || !oldAudit(journal, history).Acked || oldAudit(journal, history).Event != old || len(journal.Rows)+len(journal.History) != 2 || len(journal.Batch().Events) != 0 {
						t.Fatal("cold replay changed immutable audit/ACK")
					}
					fresh := next
					fresh.ID = strings.Repeat("f", 32)
					fresh.RecordID++
					fresh.At = fresh.At.Add(time.Second)
					if !journal.Add(fresh, now) || len(journal.Rows)+len(journal.History) != 3 || journal.Lost != 7 {
						t.Fatal("new real record lost")
					}
				}
			}
			for _, mutate := range []func(*clubhealth.Diagnostic){
				func(e *clubhealth.Diagnostic) { e.NativeCode++ }, func(e *clubhealth.Diagnostic) { e.RecordID++ }, func(e *clubhealth.Diagnostic) { e.At = e.At.Add(time.Second) },
				func(e *clubhealth.Diagnostic) { e.App = "chrome.exe" }, func(e *clubhealth.Diagnostic) { e.State = "failed" }, func(e *clubhealth.Diagnostic) { e.EventID++ },
				func(e *clubhealth.Diagnostic) { e.Operation = "UNTRUSTED_OPERATION" }, func(e *clubhealth.Diagnostic) { e.Observer = "SCM_QUERY" },
			} {
				bad := next
				bad.ID = old.ID
				mutate(&bad)
				if _, compatible := clubhealth.DiagnosticUpdate(old, bad); compatible {
					t.Fatalf("conflicting record accepted: %+v", bad)
				}
			}
		})
	}
}

func oldAudit(j clubhealth.Journal, history bool) clubhealth.JournalRow {
	if history {
		return j.History[0]
	}
	return j.Rows[0]
}
