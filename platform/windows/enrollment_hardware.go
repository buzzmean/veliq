package windowsplatform

import (
	"github.com/buzzmean/veliq/core/enrollment"
	"net"
	"sort"
)

type enrollmentAdapter struct {
	Index uint32 `json:"index"`
	Type  uint32 `json:"type"`
	Up    bool   `json:"up"`
	MAC   string `json:"mac"`
}
type enrollmentRoute struct {
	Index  uint32 `json:"index"`
	Metric uint32 `json:"metric"`
}

// Physical adapters only, supplied by Get-NetAdapter -Physical. A VPN's default
// route must not hide the underlying active Ethernet adapter. Stable MAC tie-break
// avoids selecting a different NIC merely because Windows assigned new ifIndexes.
func selectEnrollmentAdapter(adapters []enrollmentAdapter, routes []enrollmentRoute) string {
	type candidate struct {
		mac    string
		wired  bool
		routed bool
		metric uint32
	}
	candidates := []candidate{}
	for _, a := range adapters {
		m, e := net.ParseMAC(a.MAC)
		if !a.Up || e != nil || len(m) != 6 || m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" {
			continue
		}
		c := candidate{mac: m.String(), wired: a.Type == 6}
		for _, r := range routes {
			if r.Index == a.Index && (!c.routed || r.Metric < c.metric) {
				c.routed = true
				c.metric = r.Metric
			}
		}
		candidates = append(candidates, c)
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		// Preserve the existing primary physical default route when present.
		// With only a virtual VPN route, prefer the active physical Ethernet.
		if a.routed != b.routed {
			return a.routed
		}
		if a.routed && a.metric != b.metric {
			return a.metric < b.metric
		}
		if a.wired != b.wired {
			return a.wired
		}
		return a.mac < b.mac
	})
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0].mac
}

type enrollmentMetadata struct {
	UUID     string              `json:"uuid"`
	Board    string              `json:"board_serial"`
	Adapters []enrollmentAdapter `json:"adapters"`
	Routes   []enrollmentRoute   `json:"routes"`
}

func (m enrollmentMetadata) hardware() enrollment.Hardware {
	return enrollment.Hardware{UUID: m.UUID, BoardSerial: m.Board, MAC: selectEnrollmentAdapter(m.Adapters, m.Routes)}
}
