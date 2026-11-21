package clientservice

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
)

const maxApplicationProcesses = 4096
const maxRunningApplications = 128
const maxApplicationPIDs = 16
const applicationReplyBudget = 48000 // leave room for the authenticated IPC envelope

type runningApplication struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	PID          uint32   `json:"pid"`
	CreationTime uint64   `json:"creation_time"`
	PIDs         []uint32 `json:"pids"`
	ProcessCount int      `json:"process_count"`
}
type runningApplicationList struct {
	Applications []runningApplication `json:"applications"`
	Truncated    bool                 `json:"truncated"`
}

// The chooser is a metadata view of existing discovery, never a second scanner.
// Session zero, inaccessible identities, OS hosts and our own executables are
// excluded. Names come from the path, not a potentially inconsistent Name field.
func runningApplications(all []windowsplatform.ProcessIdentity, interactive func(uint32) bool, limit int) runningApplicationList {
	out := runningApplicationList{Applications: []runningApplication{}}
	if len(all) > maxApplicationProcesses {
		all = all[:maxApplicationProcesses]
		out.Truncated = true
	}
	groups := map[string]*runningApplication{}
	seen := map[uint32]bool{}
	for _, id := range all {
		p := strings.ReplaceAll(id.Path, "/", `\`)
		// Discovery returns DOS paths. Device/relative/control-character paths are
		// not executable identities usable by a normal, unelevated desktop.
		if id.PID <= 4 || id.CreationTime == 0 || len(p) > 2048 || len(p) < 7 || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || p[1:3] != `:\` || strings.ContainsAny(p[3:], `:"<>|?*`) || strings.ContainsFunc(p, unicode.IsControl) || !strings.HasSuffix(strings.ToLower(p), ".exe") {
			continue
		}
		name := p[strings.LastIndex(p, `\`)+1:]
		if hiddenApplication(name) || seen[id.PID] || !interactive(id.PID) {
			continue
		}
		seen[id.PID] = true
		key := strings.ToLower(p)
		a := groups[key]
		if a == nil {
			a = &runningApplication{Name: name, Path: p, PID: id.PID, CreationTime: id.CreationTime, PIDs: []uint32{}}
			groups[key] = a
		}
		a.ProcessCount++
		if id.PID < a.PID {
			a.PID = id.PID
			a.CreationTime = id.CreationTime
		}
		// Keep the lowest PIDs deterministically without an unbounded PID array.
		a.PIDs = append(a.PIDs, id.PID)
		sort.Slice(a.PIDs, func(i, j int) bool { return a.PIDs[i] < a.PIDs[j] })
		if len(a.PIDs) > maxApplicationPIDs {
			a.PIDs = a.PIDs[:maxApplicationPIDs]
		}
	}
	rows := make([]runningApplication, 0, len(groups))
	for _, a := range groups {
		rows = append(rows, *a)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := strings.ToLower(rows[i].Name), strings.ToLower(rows[j].Name)
		if a == b {
			return strings.ToLower(rows[i].Path) < strings.ToLower(rows[j].Path)
		}
		return a < b
	})
	size := 0
	for _, a := range rows {
		raw, _ := json.Marshal(a)
		if len(out.Applications) >= limit || size+len(raw)+1 > applicationReplyBudget {
			out.Truncated = true
			break
		}
		size += len(raw) + 1
		out.Applications = append(out.Applications, a)
	}
	return out
}
func hiddenApplication(name string) bool {
	switch strings.ToLower(name) {
	case "system", "idle", "system.exe", "idle.exe", "svchost.exe", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe", "taskhostw.exe", "dllhost.exe", "rundll32.exe", "runtimebroker.exe", "conhost.exe", "wmiprvse.exe", "wudfhost.exe", "spoolsv.exe", "searchhost.exe", "searchindexer.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "msmpeng.exe", "nissrv.exe", "explorer.exe", "veliq-service.exe", "neexitlag-service.exe", "neexitlag.exe", "veliq.exe":
		return true
	}
	return false
}
