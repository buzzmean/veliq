package windowsplatform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
)

type clubHealthEventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		}
		EventID       uint32
		Level         uint32
		EventRecordID uint64
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		}
	}
	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`
			Text string `xml:",chardata"`
		}
	}
}

var clubFaultingExe = regexp.MustCompile(`(?i)\b(veliq(?:-service)?\.exe|langameservice\.exe|steam\.exe|steamwebhelper\.exe|r5apex\.exe|cs2\.exe|chrome\.exe|msedge\.exe)\b`)
var clubRequestExe = regexp.MustCompile(`(?i)([a-z0-9_-]+\.exe)(?:\s|$)`)

// Parsing only the selected providers keeps event messages, account names,
// addresses and XML from crossing the service boundary.
func decodeClubHealthEvent(channel string, raw []byte) (clubhealth.Event, bool) {
	var x clubHealthEventXML
	if xml.Unmarshal(raw, &x) != nil || x.System.EventRecordID == 0 {
		return clubhealth.Event{}, false
	}
	when, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
	if err != nil {
		return clubhealth.Event{}, false
	}
	e := clubhealth.Event{At: when.UTC(), Code: x.System.EventID}
	p := strings.ToLower(x.System.Provider.Name)
	switch p {
	case "service control manager":
		// Only termination/start-failure records establish a service fault.
		if channel != "System" || e.Code != 7000 && e.Code != 7031 && e.Code != 7034 {
			return clubhealth.Event{}, false
		}
		if len(x.EventData.Data) != 0 {
			switch strings.ToLower(x.EventData.Data[0].Text) {
			case "veliq", "veliq routing service":
				e.Kind, e.App = "veliq_crash", "veliq-service.exe"
				if e.Code == 7000 {
					e.Kind = "veliq_start_failed"
				}
			case "langameservice", "langame service":
				e.Kind, e.App = "langame_crash", "langameservice.exe"
				if e.Code == 7000 {
					e.Kind = "langame_start_failed"
				}
			}
		}
	case "application error", "application hang", "windows error reporting":
		if channel != "Application" {
			return clubhealth.Event{}, false
		}
		// WER1001 can describe a queued report, a hang or another application.
		// Only the structured faulting image (not an arbitrary mention) is used.
		for i, data := range x.EventData.Data {
			name := strings.ToLower(data.Name)
			imageField := name == "appname" || name == "applicationname" || name == "exename" ||
				(p == "windows error reporting" && name == "p1") || (i == 0 && name == "")
			if !imageField {
				continue
			}
			image := path.Base(strings.ReplaceAll(strings.TrimSpace(data.Text), "\\", "/"))
			match := clubFaultingExe.FindStringSubmatch(image)
			if len(match) != 2 || !strings.EqualFold(match[0], image) {
				continue
			}
			e.App = strings.ToLower(match[1])
			e.Kind = "application_report"
			if p == "application error" && e.Code == 1000 {
				e.Kind = "application_crash"
				if e.App == "langameservice.exe" {
					e.Kind = "langame_crash"
				} else if e.App == "veliq.exe" || e.App == "veliq-service.exe" {
					e.Kind = "veliq_crash"
				}
			}
			break
		}
	case "langameservice", "langame":
		if x.System.Level > 0 && x.System.Level <= 3 {
			e.Kind, e.App = "langame_error", "langameservice.exe"
		}
	case "microsoft-windows-kernel-power", "eventlog":
		e.Kind = "unexpected_restart"
	case "bugcheck", "microsoft-windows-wer-systemerrorreporting":
		e.Kind = "bugcheck"
	case "user32":
		e.Kind = "shutdown_requested"
		if len(x.EventData.Data) != 0 {
			action := path.Base(strings.ReplaceAll(x.EventData.Data[0].Text, "\\", "/"))
			if app := clubRequestExe.FindStringSubmatch(action); len(app) > 1 {
				e.App = strings.ToLower(app[1])
			}
		}
	case "iscsiprt", "msiscsi", "microsoft-windows-iscsiprt", "microsoft-windows-iscsinitiator-service",
		"disk", "storport", "microsoft-windows-storport", "stornvme", "storahci", "volmgr":
		e.Kind = "storage_error"
	case "ndis", "microsoft-windows-ndis", "tcpip", "microsoft-windows-tcpip",
		"microsoft-windows-dhcp-client", "dhcp-client", "e1dexpress", "e2fexpress", "rt640x64":
		e.Kind = "network_error"
	}
	if e.Kind == "" {
		return clubhealth.Event{}, false
	}
	key := channel + ":" + strconv.FormatUint(x.System.EventRecordID, 10) + ":" + when.UTC().Format(time.RFC3339Nano)
	id := sha256.Sum256([]byte(key))
	e.ID = hex.EncodeToString(id[:16])
	return e, true
}
