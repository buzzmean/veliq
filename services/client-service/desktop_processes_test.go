package clientservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/ipc"
	windowsplatform "github.com/buzzmean/veliq/platform/windows"
	"strings"
	"testing"
)

func TestDesktopProcessFilterPreservesWindowsIdentity(t *testing.T) {
	all := []windowsplatform.ProcessIdentity{{PID: 1, Path: `C:\games\game.exe`, CreationTime: 100}, {PID: 2, Path: `C:\other\game.exe`, CreationTime: 200}, {PID: 3, Path: `C:\system\other.exe`, CreationTime: 300}}
	got := filterProcesses(all, []string{`c:/games/GAME.exe`})
	if len(got) != 1 || got[0].PID != 1 || got[0].CreationTime != 100 {
		t.Fatal(got)
	}
	got = filterProcesses(all, []string{"game.exe"})
	if len(got) != 2 {
		t.Fatal(got)
	}
	if len(filterProcesses(all, nil)) != 3 {
		t.Fatal("legacy query changed")
	}
}

func TestRunningApplicationsGroupsProcessesAndPreservesIdentity(t *testing.T) {
	all := []windowsplatform.ProcessIdentity{}
	for i := uint32(10); i < 20; i++ {
		all = append(all, windowsplatform.ProcessIdentity{PID: i, Path: `C:\Apps\Chrome\chrome.exe`, CreationTime: uint64(i + 100)})
	}
	// Case/slash differences must still identify the same executable; a different
	// full path with the same basename is an independent selectable application.
	all[1].Path = `c:/APPS/Chrome/CHROME.EXE`
	all = append(all, windowsplatform.ProcessIdentity{PID: 30, Path: `D:\Other\chrome.exe`, CreationTime: 200})
	got := runningApplications(all, func(uint32) bool { return true }, 128)
	if got.Truncated || len(got.Applications) != 2 {
		t.Fatal(got)
	}
	a := got.Applications[0]
	if a.Path != `C:\Apps\Chrome\chrome.exe` || a.ProcessCount != 10 || len(a.PIDs) != 10 || a.PID != 10 || a.CreationTime != 110 {
		t.Fatal(a)
	}
}
func TestRunningApplicationsFiltersSystemAndInvalidIdentities(t *testing.T) {
	all := []windowsplatform.ProcessIdentity{{PID: 50, Path: `C:\Apps\game.exe`, CreationTime: 1}}
	for i, n := range []string{"System", "Idle", "svchost.exe", "lsass.exe", "services.exe", "dwm.exe", "NeExitLag.exe", "VELIQ.exe", "neexitlag-service.exe", "RuntimeBroker.exe"} {
		all = append(all, windowsplatform.ProcessIdentity{PID: uint32(i + 100), Path: `C:\Windows\System32\` + n, CreationTime: 1})
	}
	for i, p := range []string{"", "relative.exe", `C:game.exe`, `\\device\game.exe`, `C:\game.txt`, "C:\\bad\nname.exe", `C:\game.exe:ads.exe`} {
		all = append(all, windowsplatform.ProcessIdentity{PID: uint32(i + 200), Path: p, CreationTime: 1})
	}
	all = append(all, windowsplatform.ProcessIdentity{PID: 300, Path: `C:\service\third-party.exe`, CreationTime: 1}, windowsplatform.ProcessIdentity{PID: 301, Path: `C:\game.exe`}, windowsplatform.ProcessIdentity{PID: 4, Path: `C:\System.exe`, CreationTime: 1})
	got := runningApplications(all, func(pid uint32) bool { return pid != 300 }, 128)
	if len(got.Applications) != 1 || got.Applications[0].PID != 50 {
		t.Fatal(got)
	}
}
func TestRunningApplicationReplyIsBoundedAndSorted(t *testing.T) {
	all := []windowsplatform.ProcessIdentity{}
	for i := uint32(10); i < 300; i++ {
		all = append(all, windowsplatform.ProcessIdentity{PID: i, Path: fmt.Sprintf(`C:\Apps\%04d\%s.exe`, 300-i, strings.Repeat("a", 1800)), CreationTime: 1})
	}
	got := runningApplications(all, func(uint32) bool { return true }, 128)
	raw, e := json.Marshal(got)
	if e != nil || !got.Truncated || len(raw) > applicationReplyBudget+100 || len(got.Applications) > 128 || len(got.Applications) == 0 {
		t.Fatal(len(raw), len(got.Applications), e)
	}
	var frame bytes.Buffer
	if err := ipc.Write(&frame, ipc.Response{Version: ipc.Version, ID: strings.Repeat("i", 128), OK: true, Data: got}); err != nil {
		t.Fatal("bounded application response cannot cross IPC", err)
	}
	for i := 1; i < len(got.Applications); i++ {
		if got.Applications[i-1].Path > got.Applications[i].Path {
			t.Fatal("unsorted")
		}
	}
	repeated := []windowsplatform.ProcessIdentity{}
	for i := uint32(10); i < maxApplicationProcesses+20; i++ {
		repeated = append(repeated, windowsplatform.ProcessIdentity{PID: i, Path: `C:\chrome.exe`, CreationTime: 1})
	}
	got = runningApplications(repeated, func(uint32) bool { return true }, 128)
	if !got.Truncated || len(got.Applications) != 1 || len(got.Applications[0].PIDs) != maxApplicationPIDs || got.Applications[0].ProcessCount != maxApplicationProcesses {
		t.Fatal(got)
	}
}
func TestProcessesQueryKeepsLegacyArrayContract(t *testing.T) {
	all := []windowsplatform.ProcessIdentity{{PID: 10, Path: `C:\game.exe`, CreationTime: 1}, {PID: 11, Path: `C:\other.exe`, CreationTime: 2}}
	discover := func() ([]windowsplatform.ProcessIdentity, error) { return all, nil }
	for _, raw := range []string{"null", `{}`, `{"executables":["game.exe"]}`} {
		got, e := listProcessesFrom(json.RawMessage(raw), discover, func(uint32) bool { return true })
		ids, ok := got.([]windowsplatform.ProcessIdentity)
		if e != nil || !ok || len(ids) == 0 {
			t.Fatal(got, e)
		}
		if strings.Contains(raw, "game.exe") && len(ids) != 1 {
			t.Fatal(ids)
		}
	}
	got, e := listProcessesFrom(json.RawMessage(`{"applications":true,"limit":1}`), discover, func(uint32) bool { return true })
	result, ok := got.(runningApplicationList)
	if e != nil || !ok || len(result.Applications) != 1 || !result.Truncated {
		t.Fatal(got, e)
	}
	for _, raw := range []string{`{"applications":true,"limit":129}`, `{"applications":true,"limit":-1}`, `{"limit":1}`, `{"applications":true,"executables":["game.exe"]}`, `{"applications":true,"unknown":true}`} {
		_, e := listProcessesFrom(json.RawMessage(raw), func() ([]windowsplatform.ProcessIdentity, error) {
			t.Fatal("invalid query reached discovery")
			return nil, nil
		}, func(uint32) bool { return true })
		if e == nil {
			t.Fatal("invalid query accepted", raw)
		}
	}
}

func TestProcessFamilyRequiresEveryExactParentBirth(t *testing.T) {
	all := []windowsplatform.ProcessIdentity{{PID: 1, CreationTime: 10, Path: "chrome.exe"}, {PID: 2, CreationTime: 20, ParentPID: 1, ParentCreationTime: 10, Path: "chrome.exe"}, {PID: 3, CreationTime: 30, ParentPID: 2, ParentCreationTime: 19, Path: "chrome.exe"}, {PID: 4, CreationTime: 20, Path: "chrome.exe"}}
	result := processFamily(all, 1, 10)
	if len(result) != 2 {
		t.Fatal("foreign/reused process borrowed trial scope", result)
	}
	if len(processFamily(all, 1, 11)) != 0 {
		t.Fatal("reused root PID accepted")
	}
}
