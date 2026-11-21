package clientservice

import (
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"strings"
)

// This is a bounded retained evidence census, not lifetime flow frequency. No
// inference from TLS type23 to HTTP redirect or from a reset to an ISP culprit.
type localLayerAudit struct {
	RetainedFlows, InspectionUnavailable, PureTSInspectionUnavailable, PlanUnavailable, PureTS, PureTSMissingPayloadTimestamp, PureTSNegotiationUnknown, PureTSNotNegotiated uint64
	TimestampOptionRequired, TimestampOptionRequiredProbes, EarlyRetransmitCandidates, SmallRSTCandidates, LateFailuresAfterReply, Freeze16To20KiB                           uint64
	Scope                                                                                                                                                                    string
}

func pureTimestamp(actions []localstrategy.Action) bool {
	for _, a := range actions {
		f := a.Fooling
		if a.Native != nil {
			f = a.Native.Fooling
		}
		if f == "ts" {
			return true
		}
	}
	return false
}
func auditLayerFlow(a *localLayerAudit, actions []localstrategy.Action, i *localstrategy.Inspection, reason string, rx uint64) {
	a.RetainedFlows++
	if len(actions) == 0 {
		a.PlanUnavailable++
	}
	pure := pureTimestamp(actions)
	if pure {
		a.PureTS++
	}
	if i == nil {
		a.InspectionUnavailable++
		if pure {
			a.PureTSInspectionUnavailable++
		}
		return
	}
	p := i.TCPPackets
	if pure {
		if !i.TimestampOption {
			a.PureTSMissingPayloadTimestamp++
		}
		if !p.ClientSYNSeen || !p.RemoteSYNSeen {
			a.PureTSNegotiationUnknown++
		} else if !p.ClientSYNTimestamp || !p.RemoteSYNTimestamp {
			a.PureTSNotNegotiated++
		}
	}
	if i.Reason == "TIMESTAMP_OPTION_REQUIRED" {
		a.TimestampOptionRequired++
	}
	if p.ClientEarlyRetransmits >= 3 {
		a.EarlyRetransmitCandidates++
	}
	if p.RemoteRST > 0 && p.RemoteRSTRelativeKnown && p.RemoteRSTRelative <= 4096 {
		a.SmallRSTCandidates++
	}
	failed := strings.Contains(reason, "STALL") || strings.Contains(reason, "TIMEOUT") || strings.Contains(reason, "RST")
	if failed && rx > 0 {
		a.LateFailuresAfterReply++
	}
	if failed && rx >= 16*1024 && rx <= 20*1024 {
		a.Freeze16To20KiB++
	}
}
func (r *youtubeRuntime) layerAuditLocked() localLayerAudit {
	a := localLayerAudit{Scope: "retained LOCAL records only; unknown negotiation is NOT missing timestamps; retransmits/RST are candidates, not DPI proof; HTTPS redirects not observable; no route changes"}
	for _, v := range r.records {
		if v.Stage != "LOCAL" {
			continue
		}
		var actions []localstrategy.Action
		if p, ok := r.plans[v.Strategy]; ok {
			actions = p.Actions
		}
		auditLayerFlow(&a, actions, v.Inspection, v.Reason, v.RX)
	}
	for _, v := range r.probeEvidence {
		if v.Inspection != nil && v.Inspection.Reason == "TIMESTAMP_OPTION_REQUIRED" {
			a.TimestampOptionRequiredProbes++
		}
	}
	return a
}
