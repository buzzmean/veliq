package localstrategy

import "strconv"

// These plans are separate from Compile's TCP runtime candidates. Availability
// here means packet construction only: hostlists are retained as source metadata,
// never used to authorize browser traffic or silently expanded to every origin.
type QUICCatalogPlan struct {
	Rule, Source, Revision string
	Repeats                uint8
	HostLists              []string
}
type QUICPlanCapability struct {
	Rule, Reason          string
	PacketPlanAvailable   bool
	BrowserRuntimeEnabled bool
}

func (c Catalog) QUICProbePlans() ([]QUICCatalogPlan, []QUICPlanCapability) {
	var plans []QUICCatalogPlan
	var caps []QUICPlanCapability
	for _, r := range c.Rules {
		quic := false
		for _, a := range r.Applies {
			quic = quic || a == "quic443"
		}
		if !quic {
			continue
		}
		plan, reason := r.quicProbePlan()
		cap := QUICPlanCapability{Rule: r.ID, Reason: reason}
		if reason == "" {
			cap.PacketPlanAvailable = true
			cap.Reason = "OWN_QUIC_PROBE_PLAN_ONLY; BROWSER_USES_TCP_FALLBACK"
			plans = append(plans, plan)
		}
		caps = append(caps, cap)
	}
	return plans, caps
}

func (r CatalogRule) quicProbePlan() (QUICCatalogPlan, string) {
	bad := func(reason string) (QUICCatalogPlan, string) { return QUICCatalogPlan{}, reason }
	if r.Source != "flowseal" || len(r.Applies) != 1 || r.Applies[0] != "quic443" {
		return bad("QUIC_SOURCE_OR_SCOPE_UNSUPPORTED")
	}
	for key, values := range r.Options {
		switch key {
		case "filter-udp", "dpi-desync", "dpi-desync-repeats", "dpi-desync-fake-quic":
			if len(values) != 1 {
				return bad("QUIC_AMBIGUOUS_PARAMETER")
			}
		case "hostlist":
			if len(values) == 0 || len(values) > 2 {
				return bad("QUIC_HOSTLIST_UNSUPPORTED")
			}
			for _, v := range values {
				if v != "%LISTS%list-general.txt" && v != "%LISTS%list-general-user.txt" {
					return bad("QUIC_HOSTLIST_UNSUPPORTED")
				}
			}
		default:
			return bad("QUIC_UNSUPPORTED_PARAMETER")
		}
	}
	get := func(k string) string {
		v := r.Options[k]
		if len(v) != 1 {
			return ""
		}
		return v[0]
	}
	if get("filter-udp") != "443" || get("dpi-desync") != "fake" || get("dpi-desync-fake-quic") != "%BIN%quic_initial_www_google_com.bin" {
		return bad("QUIC_MODE_OR_MODEL_UNSUPPORTED")
	}
	n, err := strconv.ParseUint(get("dpi-desync-repeats"), 10, 8)
	if err != nil || n < 1 || n > QUICProbeMaxRepeats {
		return bad("QUIC_REPEATS_OUTSIDE_1_16")
	}
	return QUICCatalogPlan{Rule: r.ID, Source: r.Source, Revision: r.Revision, Repeats: uint8(n), HostLists: append([]string(nil), r.Options["hostlist"]...)}, ""
}
