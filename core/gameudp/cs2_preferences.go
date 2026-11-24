package gameudp

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// The compatibility sidecar contains only a confirmed ordinary local route,
// never a live socket, join claim for the next match, timeout or pending trial.
type CS2Preference struct {
	Network     string         `json:"network"`
	Destination netip.AddrPort `json:"destination"`
	Stage       string         `json:"stage"`
	ConfirmedAt time.Time      `json:"confirmed_at"`
}

func (e *Engine) CS2Preferences(now time.Time) []CS2Preference {
	e.mu.Lock()
	defer e.mu.Unlock()
	var rows []CS2Preference
	for _, row := range e.cs2Endpoints {
		if row.Outcome == "JOINED" && now.Before(row.ObservedAt.Add(cs2EvidenceTTL)) {
			rows = append(rows, CS2Preference{row.Network, row.Destination, row.Stage, row.ObservedAt})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Network != rows[j].Network {
			return rows[i].Network < rows[j].Network
		}
		return rows[i].Destination.Compare(rows[j].Destination) < 0
	})
	return rows
}

func (e *Engine) RestoreCS2Preferences(application string, rows []CS2Preference, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	image := Canonical(application)
	if !e.cs2Auto || image != Canonical(e.application) || !strings.HasSuffix(image, "/cs2.exe") ||
		len(rows) > cs2MaxEndpoints {
		return errors.New("CS2_PREFERENCES_INVALID")
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		_, err := hex.DecodeString(row.Network)
		key := endpointKey(row.Network, image, row.Destination.String())
		if len(row.Network) != 64 || err != nil || !Eligible(image, image, "udp", row.Destination) ||
			(row.Stage != Direct && row.Stage != LocalSocket) || seen[key] ||
			row.ConfirmedAt.IsZero() || row.ConfirmedAt.After(now) {
			return errors.New("CS2_PREFERENCES_INVALID")
		}
		seen[key] = true
	}
	for _, f := range e.flows {
		delete(seen, endpointKey(f.key.Network, f.key.Application, f.key.Destination.String()))
	}
	if e.cs2Endpoints == nil {
		e.cs2Endpoints = make(map[string]CS2Endpoint)
	}
	for _, row := range rows {
		key := endpointKey(row.Network, image, row.Destination.String())
		if _, live := e.cs2Endpoints[key]; live || !seen[key] || !now.Before(row.ConfirmedAt.Add(cs2EvidenceTTL)) ||
			len(e.cs2Endpoints) >= cs2MaxEndpoints {
			continue
		}
		e.cs2Endpoints[key] = CS2Endpoint{Network: row.Network, Destination: row.Destination, Stage: row.Stage,
			ObservedAt: row.ConfirmedAt, Outcome: "JOINED", restored: true}
	}
	return nil
}
