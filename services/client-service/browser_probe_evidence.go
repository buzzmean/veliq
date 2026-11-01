package clientservice

import (
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/netdiagnostic"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"
)

type localProbeEvidence struct {
	Network        string                    `json:"network"`
	Profile        string                    `json:"profile"`
	Diagnosis      netdiagnostic.Diagnosis   `json:"diagnosis"`
	Failure        string                    `json:"failure,omitempty"`
	HTTPStatus     int                       `json:"http_status"`
	TLSVersion     uint16                    `json:"tls_version"`
	PlannedActions []localstrategy.Action    `json:"planned_actions,omitempty"`
	Sent           uint64                    `json:"sent_bytes"`
	At             time.Time                 `json:"at"`
	Strategy       string                    `json:"strategy"`
	Host           string                    `json:"host"`
	Service        string                    `json:"service"`
	Result         string                    `json:"result"`
	Phase          string                    `json:"phase"`
	Detail         string                    `json:"detail"`
	Received       uint64                    `json:"received_bytes"`
	Body           uint64                    `json:"body_bytes"`
	Committed      bool                      `json:"committed"`
	Inspection     *localstrategy.Inspection `json:"inspection,omitempty"`
}

func localProbeOutcome(p browserproxy.ProbeResult, applied bool) string {
	if p.Phase == "ORIGIN_DNS" {
		return "ORIGIN_DNS_FAILED"
	}
	if p.Phase == "LOCAL_GUARD" {
		return "LOCAL_GUARD"
	}
	if p.Failure == "" && (p.Phase == "PUBLIC_WS_CONTROL" || p.Phase == "PUBLIC_REDIRECT_CONTROL") {
		if applied {
			return "OK_CONTROL_NOT_BULK"
		}
		return "NO_TRANSFORM"
	}
	if p.Detail == "PEER_RESET" {
		return "RST"
	}
	if p.Bytes == 0 && p.Failure != "" {
		return "ORIGIN_SILENT"
	}
	if p.BodyBytes > 0 && p.Failure != "" {
		if p.Failure == "NETWORK_TIMEOUT" {
			return "FREEZE_AFTER_N"
		}
		if p.Detail == "PEER_CLOSED" {
			return "EOF_AFTER_N"
		}
		return "ORIGIN_PROTOCOL_OR_BODY_FAILED"
	}
	if p.BodyBytes > 0 && p.BodyBytes <= 64*1024 {
		return "SHORT_RESPONSE"
	}
	if !applied {
		return "NO_TRANSFORM"
	}
	if youtubeTransferOK(p) {
		return "OK"
	}
	return "ORIGIN_RESPONSE_NOT_SUSTAINED"
}
func (c *Controller) localPacketInspection(q browserproxy.Request, p browserproxy.Plan) *localstrategy.Inspection {
	if b, ok := c.Backend.(interface {
		BrowserLocalInspection(wp.ProcessIdentity, netip.AddrPort, netip.AddrPort) *localstrategy.Inspection
	}); ok {
		return b.BrowserLocalInspection(browserIdentity(q), q.Source, p.Destination)
	}
	return nil
}
func (c *Controller) recordLocalProbe(q browserproxy.Request, p browserproxy.Plan, strategy string, result browserproxy.ProbeResult, applied bool, sent ...uint64) {
	inspection := c.localPacketInspection(q, p)
	row := localProbeEvidence{Failure: result.Failure, HTTPStatus: result.Status, TLSVersion: result.TLSVersion, At: time.Now(), Strategy: strategy, Host: q.Host, Service: c.browserOriginPolicy(q.Host).Group, Result: localProbeOutcome(result, applied), Phase: result.Phase, Detail: result.Detail, Received: result.Bytes, Body: result.BodyBytes, Committed: applied, Inspection: inspection}
	row.Network, row.Profile, row.Diagnosis = p.Network, q.Owner.Profile, netdiagnostic.DiagnoseProbe(result)
	if len(sent) > 0 {
		row.Sent = sent[0]
	}
	r := c.browser.youtube
	r.mu.Lock()
	defer r.mu.Unlock()
	if plan, ok := r.plans[strategy]; ok {
		row.PlannedActions = append([]localstrategy.Action(nil), plan.Actions...)
	} else {
		for _, candidate := range localstrategy.BrowserYouTubeCandidates() {
			if candidate.ID == strategy {
				row.PlannedActions = append([]localstrategy.Action(nil), candidate.Actions...)
			}
		}
	}
	if applied && youtubeDomain(q.Host) && p.Network != "" {
		for k, until := range r.qualifications {
			if !time.Now().Before(until) {
				delete(r.qualifications, k)
			}
		}
		key := youtubeQualification{p.Network, q.Owner.Profile, strategy, q.HintOnly}
		_, exists := r.qualifications[key]
		if len(r.qualifications) < 256 || exists {
			r.qualifications[key] = time.Now().Add(youtubeLearnTTL)
			if youtubeTransferOK(result) {
				r.sustained[key] = time.Now().Add(youtubeLearnTTL)
			}
			for k, until := range r.sustained {
				if !time.Now().Before(until) {
					delete(r.sustained, k)
				}
			}
		}
	}
	r.probeEvidence = append(r.probeEvidence, row)
	if len(r.probeEvidence) > 128 {
		r.probeEvidence = append([]localProbeEvidence(nil), r.probeEvidence[len(r.probeEvidence)-128:]...)
	}
}

type localProbeConn struct {
	net.Conn
	sent atomic.Uint64
}

func (c *localProbeConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.sent.Add(uint64(n))
	return n, e
}

type localCloseEvidence struct {
	Domain, Strategy, Reason, IOFailure string
	Timing                              youtubeTimings
	OpenMS, TransformSendMS             float64
	TX, RX                              uint64
	Updated                             time.Time
	Packets                             localstrategy.TCPTrace
}

func (c *Controller) localProbeSnapshot() map[string]any {
	r := c.browser.youtube
	r.mu.Lock()
	defer r.mu.Unlock()
	closed := []localCloseEvidence{}
	for _, v := range r.records {
		if v.Stage == "LOCAL" && v.Inspection != nil && (!v.Active || v.IOFailure != "") {
			closed = append(closed, localCloseEvidence{Domain: v.Domain, Strategy: v.Strategy, Reason: v.Reason, IOFailure: v.IOFailure, TX: v.TX, RX: v.RX, Updated: v.Updated, Packets: v.Inspection.TCPPackets, Timing: v.Timing, OpenMS: v.OpenMS, TransformSendMS: v.Inspection.TransformSendMS})
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].Updated.After(closed[j].Updated) })
	if len(closed) > 8 {
		closed = closed[:8]
	}
	rows := append([]localProbeEvidence(nil), r.probeEvidence...)
	if len(rows) > 32 {
		rows = rows[len(rows)-32:]
	}
	recentFailures := r.failures
	if len(recentFailures) > 8 {
		recentFailures = recentFailures[len(recentFailures)-8:]
	}
	trialRows := append([]cdnTrialEvidence(nil), r.trials...)
	for i := range trialRows {
		if v, ok := r.records[trialRows[i].ID]; ok && v.Active {
			trialRows[i].DataTrial = v.DataTrial
			if v.TrialResult != "" {
				trialRows[i].TrialResult = v.TrialResult
			}
			trialRows[i].TX = v.TX
			trialRows[i].RX = v.RX
			trialRows[i].Timing = v.Timing
			trialRows[i].Updated = v.Updated
		}
	}
	sort.Slice(trialRows, func(i, j int) bool {
		if !trialRows[i].Updated.Equal(trialRows[j].Updated) {
			return trialRows[i].Updated.After(trialRows[j].Updated)
		}
		return trialRows[i].ID > trialRows[j].ID
	})
	if len(trialRows) > 8 {
		trialRows = trialRows[:8]
	}
	ordinary := append([]ordinaryFlowEvidence(nil), r.ordinary...)
	for i := range ordinary {
		ordinary[i].Addresses = append([]ordinaryAddressEvidence(nil), ordinary[i].Addresses...)
	}
	if len(ordinary) > 16 {
		ordinary = ordinary[len(ordinary)-16:]
	}
	endpointNegatives := []cdnEndpointFailure{}
	for _, v := range r.endpointNegative {
		if time.Now().Before(v.Until) {
			endpointNegatives = append(endpointNegatives, v)
		}
	}
	sort.Slice(endpointNegatives, func(i, j int) bool { return endpointNegatives[i].Until.After(endpointNegatives[j].Until) })
	if len(endpointNegatives) > 8 {
		endpointNegatives = endpointNegatives[:8]
	}
	ordinaryLadder := []youtubeRecord{}
	for _, v := range r.records {
		if v.Service == "ordinary" {
			v.Inspection = nil
			v.Failure = nil
			ordinaryLadder = append(ordinaryLadder, v)
		}
	}
	sort.Slice(ordinaryLadder, func(i, j int) bool { return ordinaryLadder[i].ID > ordinaryLadder[j].ID })
	if len(ordinaryLadder) > 16 {
		ordinaryLadder = ordinaryLadder[:16]
	}
	result := map[string]any{"layer_audit": r.layerAuditLocked(), "ordinary_dns_direct_attempts": r.ordinaryDirectAttempts, "ordinary_scope_denials": r.ordinaryDenials, "ordinary_ladder": ordinaryLadder, "cdn_endpoint_negatives": endpointNegatives, "ordinary_retained": len(r.ordinary), "ordinary": ordinary, "trials": trialRows, "failures": recentFailures, "tcp_closures": closed, "probes": rows, "retained": len(r.probeEvidence), "retention_limit": 128, "scope": "bounded recent probes and closes; headers/timing only; TLS1.3 type23 is NOT HTTP content proof"}
	for {
		result["ordinary_omitted"] = len(r.ordinary) - len(ordinary)
		result["probes"] = rows
		result["tcp_closures"] = closed
		result["omitted_retained"] = len(r.probeEvidence) - len(rows)
		raw, _ := json.Marshal(result)
		if len(raw) < 48000 {
			return result
		}
		// Compact route/identity evidence outranks large packet traces. In .15
		// ordinary was removed FIRST and the script mislabeled it NONE_RECORDED.
		if len(rows) > 0 {
			rows = rows[1:]
		} else if len(closed) > 0 {
			closed = closed[:len(closed)-1]
		} else if len(ordinaryLadder) > 4 {
			ordinaryLadder = ordinaryLadder[:len(ordinaryLadder)-1]
			result["ordinary_ladder"] = ordinaryLadder
		} else if len(ordinary) > 4 {
			ordinary = ordinary[1:]
			result["ordinary"] = ordinary
		} else if len(trialRows) > 1 {
			trialRows = trialRows[:len(trialRows)-1]
			result["trials"] = trialRows
		} else if len(endpointNegatives) > 0 {
			endpointNegatives = endpointNegatives[:len(endpointNegatives)-1]
			result["cdn_endpoint_negatives"] = endpointNegatives
		} else if len(ordinaryLadder) > 0 {
			ordinaryLadder = ordinaryLadder[:len(ordinaryLadder)-1]
			result["ordinary_ladder"] = ordinaryLadder
		} else if len(ordinary) > 0 {
			ordinary = ordinary[1:]
			result["ordinary"] = ordinary
		} else if len(trialRows) > 0 {
			trialRows = nil
			result["trials"] = trialRows
		} else {
			return result
		}
	}
}
