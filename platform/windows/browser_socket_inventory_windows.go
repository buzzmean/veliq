//go:build windows

package windowsplatform

import "fmt"

func BrowserTCPSockets() ([]BrowserTCPSocket, bool, error) {
	rows, err := queryOwnedTCP()
	if err != nil {
		return nil, false, fmt.Errorf("BROWSER_TCP_INVENTORY_FAILED: %w", err)
	}
	out := []BrowserTCPSocket{}
	ids := map[uint32]ProcessIdentity{}
	for _, row := range rows {
		id, ok := ids[row.PID]
		if !ok {
			id, _ = NewDiscovery().Lookup(row.PID)
			ids[row.PID] = id
		}
		if !browserProcess(id) {
			continue
		}
		if len(out) == 24 {
			return out, true, nil
		}
		out = append(out, BrowserTCPSocket{Identity: id, Tuple: row.Tuple, State: row.State})
	}
	return out, false, nil
}
