package windowsplatform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
)

func decodeDiagnosticEvent(channel string, raw []byte, lookup func(uint32) (ProcessIdentity, error)) (clubhealth.Diagnostic, bool) {
	var x clubHealthEventXML
	if xml.Unmarshal(raw, &x) != nil || x.System.EventRecordID == 0 {
		return clubhealth.Diagnostic{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
	if err != nil {
		return clubhealth.Diagnostic{}, false
	}
	key := channel + ":" + strconv.FormatUint(x.System.EventRecordID, 10) + ":" + at.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(key))
	e := clubhealth.Diagnostic{ID: hex.EncodeToString(sum[:16]), At: at.UTC(), State: "observed", Observer: "WINDOWS_EVENT_LOG", RecordID: x.System.EventRecordID, EventID: x.System.EventID}
	if strings.EqualFold(x.System.Provider.Name, "Schannel") {
		e.Component, e.Code = "TLS", "SCHANNEL_EVENT"
		var claimedName string
		for _, d := range x.EventData.Data {
			switch strings.ToLower(d.Name) {
			case "errorcode", "status":
				if e.NativeCode == 0 {
					v, _ := strconv.ParseUint(strings.TrimSpace(d.Text), 0, 32)
					e.NativeCode = uint32(v)
				}
			case "errorstate":
				v, _ := strconv.ParseUint(strings.TrimSpace(d.Text), 0, 32)
				e.ProviderState = uint32(v)
			case "callerprocessid":
				v, _ := strconv.ParseUint(strings.TrimSpace(d.Text), 0, 32)
				e.PID = uint32(v)
			case "callerprocessimage", "callerprocessname", "processname":
				claimedName = strings.ToLower(d.Text[strings.LastIndexAny(d.Text, `/\`)+1:])
			}
		}
		if e.EventID == 36876 {
			e.Operation = "CERTIFICATE_VALIDATION"
		}
		if e.NativeCode == 0x80092013 {
			e.Code = "CRYPT_E_REVOCATION_OFFLINE"
		}
		for _, d := range x.EventData.Data {
			if strings.EqualFold(d.Name, "ErrorCode") {
				v, err := strconv.ParseUint(strings.TrimSpace(d.Text), 0, 32)
				if err == nil {
					e.NativeCode = uint32(v)
				}
			}
		}
		// System.Execution.ProcessID is often LSASS, not the caller. Never use it.
		if e.PID != 0 && lookup != nil {
			id, err := lookup(e.PID)
			name := strings.ToLower(id.Path[strings.LastIndexAny(id.Path, `/\`)+1:])
			// FILETIME identifies this process generation. A reused PID born after
			// the event cannot be the caller. An explicit image must also agree.
			born := time.Unix(0, int64(id.CreationTime-116444736000000000)*100)
			if err == nil && id.CreationTime >= 116444736000000000 && !born.After(at) &&
				clubhealth.ValidApp(name) && (claimedName == "" || claimedName == name) {
				e.App, e.Birth, e.ProcessVerified = name, id.CreationTime, true
			}
		}
		return e, true // An isolated TLS error has no provable recovery signal.
	}
	old, ok := decodeClubHealthEvent(channel, raw)
	if !ok {
		return e, false
	}
	e.Component = "WINDOWS"
	e.Code = strings.ToUpper(old.Kind)
	e.App = old.App
	switch old.Kind {
	case "storage_error":
		e.Component = "STORAGE_ISCSI"
	case "network_error":
		e.Component = "NETWORK"
	case "langame_crash", "langame_start_failed", "langame_error":
		e.Component = "LANGAME"
	case "veliq_crash", "veliq_start_failed":
		e.Component = "SERVICE"
	case "application_crash", "application_report":
		e.Component = "APPLICATION"
	}
	if strings.EqualFold(x.System.Provider.Name, "Application Error") && e.EventID == 1000 {
		e.Operation = "APPLICATION_FAULT"
	} else if strings.EqualFold(x.System.Provider.Name, "Service Control Manager") {
		if e.EventID == 7000 {
			e.Operation = "SERVICE_START_FAILURE"
		} else {
			e.Operation = "SERVICE_TERMINATION"
		}
	}
	// A classifier correction is a new interpretation, not a replacement of
	// old immutable audit bytes. A fixed namespace avoids conflicts with old
	// journals/CPs even when only the server retains the original record.
	// The physical record key remains channel/record/time; build/session are
	// deliberately absent, so replay never creates another interpretation.
	if e.Operation != "" || e.Code == "APPLICATION_REPORT" {
		sum := sha256.Sum256([]byte("windows-event-interpretation-v2:" + e.ID))
		e.ID = hex.EncodeToString(sum[:16])
	}
	// Only named numeric fields; never arbitrary text/exception messages.
	for _, d := range x.EventData.Data {
		if strings.EqualFold(d.Name, "ExceptionCode") || strings.EqualFold(d.Name, "Status") {
			v, err := strconv.ParseUint(strings.TrimSpace(d.Text), 0, 32)
			if err == nil {
				e.NativeCode = uint32(v)
			}
		}
	}
	return e, true
}
