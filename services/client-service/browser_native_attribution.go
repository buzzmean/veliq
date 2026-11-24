package clientservice

import (
	"encoding/json"
	wp "github.com/buzzmean/veliq/platform/windows"
)

// Deliberately opt-in read-only IPC, not a process scanner in the GUI poll loop.
func (c *Controller) nativeBrowserAttribution() any {
	rows, truncated, err := wp.BrowserTCPSockets()
	out := map[string]any{"scope": "LIVE_IPV4_TCP_OWNER_TABLE_NOT_CAPTURE_OR_PAGE_PROOF", "truncated": truncated, "records": []any{}}
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	records := []any{}
	for _, r := range rows {
		d := c.Classify(r.Identity, r.Tuple)
		records = append(records, map[string]any{"identity": r.Identity, "source": r.Tuple.Source.String(), "destination": r.Tuple.Destination.String(), "tcp_state": r.State, "loopback": r.Tuple.Destination.Addr().IsLoopback(), "profile_id": d.Flow.ApplicationID, "policy": d.Policy, "deferred": d.Deferred, "native_opener": d.OpenDeferred != nil, "new_connections_only": d.NewConnectionsOnly})
		out["records"] = records
		raw, _ := json.Marshal(out)
		if len(raw) > 48*1024 {
			out["records"] = records[:len(records)-1]
			out["truncated"] = true
			break
		}
	}
	return out
}
