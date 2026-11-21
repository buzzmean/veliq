package clientservice

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
)

// Optional v1 query limits desktop results to configured applications instead of
// overflowing the IPC frame with unrelated system processes. Old nil queries work.
func listProcesses(raw json.RawMessage) (any, error) {
	return listProcessesFrom(raw, windowsplatform.NewDiscovery().List, windowsplatform.InteractiveProcess)
}
func listProcessesFrom(raw json.RawMessage, discover func() ([]windowsplatform.ProcessIdentity, error), interactive func(uint32) bool) (any, error) {
	var query struct {
		RootPID      uint32   `json:"root_pid"`
		RootCreation uint64   `json:"root_creation_time"`
		Executables  []string `json:"executables"`
		Applications bool     `json:"applications"`
		Limit        int      `json:"limit"`
	}
	if len(raw) > 0 && string(raw) != "null" {
		if err := security.Parse(raw, &query); err != nil {
			return nil, err
		}
	}
	if (query.RootPID == 0) != (query.RootCreation == 0) {
		return nil, errors.New("exact root birth required")
	}
	if query.Applications {
		if query.RootPID != 0 || len(query.Executables) > 0 || query.Limit < 0 || query.Limit > maxRunningApplications {
			return nil, errors.New("invalid application query")
		}
		if query.Limit == 0 {
			query.Limit = maxRunningApplications
		}
	} else if query.Limit != 0 {
		return nil, errors.New("limit requires applications query")
	}
	if len(query.Executables) > 2048 {
		return nil, errors.New("process query limit exceeded")
	}
	for _, exe := range query.Executables {
		if len(exe) > 2048 || !strings.HasSuffix(strings.ToLower(exe), ".exe") {
			return nil, errors.New("invalid executable query")
		}
	}
	all, err := discover()
	if err != nil {
		return nil, err
	}
	if query.Applications {
		return runningApplications(all, interactive, query.Limit), nil
	}
	if query.RootPID != 0 {
		all = processFamily(all, query.RootPID, query.RootCreation)
	}
	return filterProcesses(all, query.Executables), nil
}
func filterProcesses(all []windowsplatform.ProcessIdentity, executables []string) []windowsplatform.ProcessIdentity {
	if len(executables) == 0 {
		return all
	}
	match := profiles.Profile{Executables: executables}
	result := []windowsplatform.ProcessIdentity{}
	for _, id := range all {
		if match.Matches(id) {
			result = append(result, id)
		}
	}
	return result
}

func processFamily(all []windowsplatform.ProcessIdentity, pid uint32, birth uint64) []windowsplatform.ProcessIdentity {
	byPID := map[uint32]windowsplatform.ProcessIdentity{}
	for _, v := range all {
		byPID[v.PID] = v
	}
	root, ok := byPID[pid]
	if !ok || root.CreationTime != birth {
		return []windowsplatform.ProcessIdentity{}
	}
	out := []windowsplatform.ProcessIdentity{}
	for _, v := range all {
		cur := v
		for n := 0; n < 16; n++ {
			if cur.PID == pid && cur.CreationTime == birth {
				out = append(out, v)
				break
			}
			parent, ok := byPID[cur.ParentPID]
			if !ok || parent.CreationTime != cur.ParentCreationTime || parent.CreationTime > cur.CreationTime {
				break
			}
			cur = parent
		}
	}
	return out
}
