package clientservice

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/originpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

const dpiFieldRowLimit = 1024
const dpiFieldPageSize = 32

type dpiFieldIdentity struct {
	PID   uint32 `json:"pid"`
	Birth uint64 `json:"birth"`
}

type dpiFieldAudit struct {
	mu        sync.Mutex
	root      dpiFieldIdentity
	profile   string
	owners    map[dpiFieldIdentity]bool
	rows      []*dpiFieldRow
	relayRows map[dpiFieldRelayFlow]*dpiFieldRow
	totals    dpiFieldTotals
}

type dpiFieldRow struct {
	Seq          int              `json:"seq"`
	At           time.Time        `json:"at"`
	Kind         string           `json:"kind"`
	Owner        dpiFieldIdentity `json:"owner"`
	Attribution  string           `json:"attribution"`
	Host         string           `json:"host,omitempty"`
	Destination  string           `json:"destination,omitempty"`
	Strategy     string           `json:"strategy,omitempty"`
	ConnectionID uint64           `json:"connection_id,omitempty"`
	RecordID     uint64           `json:"upstream_record_id,omitempty"`
	Relay        string           `json:"relay,omitempty"`
	Reason       string           `json:"reason,omitempty"`
	DNSPath      string           `json:"dns_path,omitempty"`
	DNSRelay     bool             `json:"dns_relay,omitempty"`
	Result       string           `json:"result,omitempty"`
	Addresses    int              `json:"addresses,omitempty"`
	QueryType    uint16           `json:"query_type,omitempty"`
	TX           uint64           `json:"tx"`
	RX           uint64           `json:"rx"`
}

type dpiFieldTotals struct {
	LocalCDNConnections uint64 `json:"local_cdn_connections"`
	LocalCDNRX          uint64 `json:"local_cdn_rx"`
	DNS                 uint64 `json:"dns"`
	RelayDNS            uint64 `json:"relay_dns_queries"`
	RelayDNSOpens       uint64 `json:"relay_dns_opens"`
	RelayOpens          uint64 `json:"relay_opens"`
	RelayRX             uint64 `json:"relay_rx"`
	RelayTX             uint64 `json:"relay_tx"`
	UnattributedRelay   uint64 `json:"unattributed_relay"`
	UnattributedIO      uint64 `json:"unattributed_relay_io"`
	Omitted             uint64 `json:"omitted"`
}

type dpiFieldRelayFlow struct {
	Key     routing.Key
	Created time.Time
}

type dpiFieldPage struct {
	Schema     int              `json:"schema"`
	Build      string           `json:"build"`
	ServicePID int              `json:"service_pid"`
	Root       dpiFieldIdentity `json:"root"`
	Totals     dpiFieldTotals   `json:"totals"`
	Rows       []dpiFieldRow    `json:"rows"`
	Next       int              `json:"next"`
	Count      int              `json:"count"`
}

// Use the existing process ancestry check, including birth of every parent.
// A positive decision is cached by PID + birth, never by executable alone.
func (a *dpiFieldAudit) attribution(owner dpiFieldIdentity, exe, profile string) string {
	a.mu.Lock()
	root, selected := a.root, a.profile
	known := a.owners[owner]
	a.mu.Unlock()
	if root.PID == 0 {
		return ""
	}
	if known {
		return "TEST_CHROME"
	}
	if !chromeExecutable(exe) {
		if exe == "" || profile == selected {
			return "UNATTRIBUTED"
		}
		return ""
	}
	if owner.PID == 0 || owner.Birth == 0 || owner.PID == root.PID {
		return "UNATTRIBUTED"
	}
	if owner.Birth < root.Birth {
		return ""
	}
	id := wp.ProcessIdentity{PID: owner.PID, CreationTime: owner.Birth, Path: exe}
	discovery, ok := wp.NewDiscovery().(interface {
		Ancestry(wp.ProcessIdentity) ([]wp.ProcessIdentity, error)
	})
	if !ok {
		return "UNATTRIBUTED"
	}
	family, err := discovery.Ancestry(id)
	if err != nil || len(family) == 0 {
		return "UNATTRIBUTED"
	}
	for _, parent := range family {
		if parent.PID == root.PID && parent.CreationTime == root.Birth {
			a.mu.Lock()
			if len(a.owners) < 256 {
				a.owners[owner] = true
			}
			a.mu.Unlock()
			return "TEST_CHROME"
		}
		if parent.CreationTime < root.Birth {
			return ""
		}
	}
	// A short chain can mean the network process outlived a parent. Do not
	// claim zero relay activity from a process with incomplete attribution.
	return "UNATTRIBUTED"
}

func chromeExecutable(path string) bool {
	path = strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	return path == "chrome.exe" || strings.HasSuffix(path, "/chrome.exe")
}

func (a *dpiFieldAudit) appendLocked(row *dpiFieldRow) *dpiFieldRow {
	if len(a.rows) >= dpiFieldRowLimit {
		a.totals.Omitted++
		return nil
	}
	row.Seq, row.At = len(a.rows)+1, time.Now().UTC()
	a.rows = append(a.rows, row)
	return row
}

func (a *dpiFieldAudit) localCDN(q browserproxy.Request, destination, strategy string, connection, record uint64) *dpiFieldRow {
	if !isVideo(q) {
		return nil
	}
	owner := dpiFieldIdentity{q.Owner.PID, q.Owner.Birth}
	if a.attribution(owner, q.Owner.Exe, q.Owner.Profile) != "TEST_CHROME" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.totals.LocalCDNConnections++
	row := &dpiFieldRow{Kind: "LOCAL_CDN", Owner: owner, Attribution: "TEST_CHROME", Host: q.Host, Destination: destination,
		Strategy: strategy, ConnectionID: connection, RecordID: record}
	// The meter still holds the row and updates the cumulative total if the
	// detail limit is reached. Readout marks the omitted detail explicitly.
	a.appendLocked(row)
	return row
}

func (a *dpiFieldAudit) localBytes(row *dpiFieldRow, tx, rx uint64) {
	if row == nil || tx == 0 && rx == 0 {
		return
	}
	a.mu.Lock()
	row.TX += tx
	row.RX += rx
	a.totals.LocalCDNRX += rx
	a.mu.Unlock()
}

func (a *dpiFieldAudit) dns(q browserproxy.Request, host, path, result string, addresses int, queryType uint16) {
	owner := dpiFieldIdentity{q.Owner.PID, q.Owner.Birth}
	class := a.attribution(owner, q.Owner.Exe, q.Owner.Profile)
	if class == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.totals.DNS++
	if path == "AUTHENTICATED_RELAY_DOH" {
		if class == "TEST_CHROME" {
			a.totals.RelayDNS++
		} else {
			a.totals.UnattributedRelay++
		}
	}
	a.appendLocked(&dpiFieldRow{Kind: "DNS", Owner: owner, Attribution: class, Host: host, DNSPath: path,
		Result: result, Addresses: addresses, QueryType: queryType})
}

func dpiFieldRelayKey(f routing.Flow) dpiFieldRelayFlow {
	return dpiFieldRelayFlow{Key: routing.Key{Protocol: f.Protocol, Source: f.Source, Destination: f.Destination, PID: f.PID}, Created: f.CreatedAt}
}

func (a *dpiFieldAudit) relayOpen(f routing.Flow) {
	owner := dpiFieldIdentity{f.PID, f.OwnerBirth}
	class := a.attribution(owner, f.ProcessPath, f.ApplicationID)
	if class == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if class == "TEST_CHROME" {
		a.totals.RelayOpens++
	} else {
		a.totals.UnattributedRelay++
	}
	dns := f.OriginReason == "RESOLVER_BOOTSTRAP" || f.OriginReason == "browser_dns_wire_doh" ||
		browserproxy.KnownDoHEndpoint(f.OriginDomain, f.Destination) || f.Destination.Port() == 53 || f.Destination.Port() == 853
	if dns && class == "TEST_CHROME" {
		a.totals.RelayDNSOpens++
	}
	row := a.appendLocked(&dpiFieldRow{Kind: "RELAY_OPEN", Owner: owner, Attribution: class, Host: f.OriginDomain,
		Destination: f.Destination.String(), Reason: f.OriginReason, Relay: f.Route.RelayID, DNSRelay: dns})
	if row != nil {
		a.relayRows[dpiFieldRelayKey(f)] = row
	}
}

func (a *dpiFieldAudit) relayBytes(f routing.Flow, tx, rx uint64) {
	owner := dpiFieldIdentity{f.PID, f.OwnerBirth}
	key := dpiFieldRelayKey(f)
	a.mu.Lock()
	if row := a.relayRows[key]; row != nil && row.Owner == owner && row.Relay == f.Route.RelayID {
		row.TX += tx
		row.RX += rx
		if row.Attribution == "TEST_CHROME" {
			a.totals.RelayTX += tx
			a.totals.RelayRX += rx
		} else {
			a.totals.UnattributedIO += tx + rx
		}
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()
	class := a.attribution(owner, f.ProcessPath, f.ApplicationID)
	if class == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if class != "TEST_CHROME" {
		a.totals.UnattributedIO += tx + rx
		return
	}
	a.totals.RelayTX += tx
	a.totals.RelayRX += rx
}

func (a *dpiFieldAudit) page(after int) (dpiFieldPage, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.root.PID == 0 || after < 0 || after > len(a.rows) {
		return dpiFieldPage{}, errors.New("DPI field session or cursor unavailable")
	}
	next := min(after+dpiFieldPageSize, len(a.rows))
	page := dpiFieldPage{Schema: 1, Build: buildStamp(), ServicePID: os.Getpid(), Root: a.root,
		Totals: a.totals, Rows: make([]dpiFieldRow, 0, next-after), Next: next, Count: len(a.rows)}
	for _, row := range a.rows[after:next] {
		page.Rows = append(page.Rows, *row)
	}
	return page, nil
}

func (c *Controller) handleDPIField(method string, raw json.RawMessage) (any, error) {
	if !browserDPIFinalEnabled() {
		return nil, errors.New("DPI field evidence is available in the PC24 test build")
	}
	a := &c.browser.dpiField
	if method == "browser.dpi_local.evidence" {
		var cursor struct {
			After int `json:"after"`
		}
		if err := security.Parse(raw, &cursor); err != nil {
			return nil, err
		}
		return a.page(cursor.After)
	}
	var root dpiFieldIdentity
	if err := security.Parse(raw, &root); err != nil {
		return nil, err
	}
	id, err := wp.NewDiscovery().Lookup(root.PID)
	if err != nil || root.Birth == 0 || id.CreationTime != root.Birth || !chromeExecutable(id.Path) || !wp.IsCurrent(id) {
		return nil, errors.New("DPI field Chrome identity mismatch")
	}
	sid, err := wp.ProcessUserSID(id)
	if err != nil || c.BrowserOwnerSID == "" || sid != c.BrowserOwnerSID {
		return nil, errors.New("DPI field Chrome owner mismatch")
	}
	profile, ok := c.matchApplication(id)
	if !ok || !nativeBrowserProfile(profile) || !chromeProfile(profile) {
		return nil, errors.New("DPI field requires the existing native Chrome AUTO profile")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.root.PID != 0 {
		return nil, errors.New("DPI field session is already registered")
	}
	a.root, a.profile = root, profile.ID
	a.owners = map[dpiFieldIdentity]bool{root: true}
	a.relayRows = make(map[dpiFieldRelayFlow]*dpiFieldRow)
	return root, nil
}

func (c *Controller) dpiFieldAncillary(q browserproxy.Request) bool {
	if !browserDPIFinalEnabled() {
		return false
	}
	switch strings.ToLower(strings.TrimSuffix(q.Host, ".")) {
	case "googleads.g.doubleclick.net", "static.doubleclick.net", "play.google.com":
	default:
		return false
	}
	return c.browserOriginPolicy(q.Host).Kind != "RELAY" && originpolicy.Floor(q.Host).Kind != "RELAY" &&
		c.browser.dpiField.attribution(dpiFieldIdentity{q.Owner.PID, q.Owner.Birth}, q.Owner.Exe, q.Owner.Profile) == "TEST_CHROME"
}

func (c *Controller) recordFieldResolverOpen(q browserproxy.Request, p browserproxy.Plan, err error) {
	if !browserDPIFinalEnabled() || p.Probe != "DPI_LOCAL_ENCRYPTED_RESOLVER" ||
		!browserproxy.KnownDoHEndpoint(q.Host, netip.AddrPortFrom(netip.Addr{}, q.Port)) {
		return
	}
	result := "TLS_TUNNEL_OPENED"
	if err != nil {
		result = "TLS_TUNNEL_FAILED"
	}
	c.browser.dpiField.dns(q, q.Host, "DIRECT_DOH_TUNNEL", result, 0, 0)
}

func (c *Controller) dpiFieldDecision(q browserproxy.Request, event cdnDecisionEvent) cdnDecisionEvent {
	if browserDPIFinalEnabled() {
		owner := dpiFieldIdentity{q.Owner.PID, q.Owner.Birth}
		if class := c.browser.dpiField.attribution(owner, q.Owner.Exe, q.Owner.Profile); class != "" {
			event.Owner, event.Attribution = &owner, class
		}
	}
	return event
}
