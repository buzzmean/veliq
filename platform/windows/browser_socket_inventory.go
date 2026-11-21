package windowsplatform

// Read-only native owner-table census, independent of packet/Engine ledgers.
// It includes Chromium utility/NetworkService children without command lines.
type BrowserTCPSocket struct {
	Identity ProcessIdentity `json:"identity"`
	Tuple    Tuple           `json:"tuple"`
	State    uint32          `json:"tcp_state"`
}
