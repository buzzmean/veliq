package netdiagnostic

import (
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"strings"
)

// Diagnosis is observed evidence, not routing authority or a second health cache.
// Encrypted TLS records cannot verify a page or a browser's playback state.
type Diagnosis struct {
	Layer            string `json:"layer"`
	State            string `json:"state"`
	PageVerified     bool   `json:"page_verified"`
	PlaybackVerified bool   `json:"playback_verified"`
}

func DiagnoseDNS(result string) Diagnosis {
	switch result {
	case "DNS_RESPONSE":
		return Diagnosis{Layer: "DNS", State: "ANSWER_OBSERVED"}
	case "DNS_NXDOMAIN", "DNS_SERVFAIL", "DNS_REFUSED", "DNS_ERROR_RESPONSE", "DNS_NODATA", "DNS_RESPONSE_NO_ADDRESS_HINTS", "DNS_TRUNCATED", "DNS_TIMEOUT", "DNS_CANCELED", "DNS_INVALID_RESPONSE":
		return Diagnosis{Layer: "DNS", State: result}
	default:
		return Diagnosis{Layer: "DNS", State: "TRANSACTION_FAILED_UNCLASSIFIED"}
	}
}

func DiagnoseProbe(p browserproxy.ProbeResult) Diagnosis {
	if p.Phase == "ORIGIN_DNS" {
		return Diagnosis{Layer: "DNS", State: "RESOLUTION_FAILED"}
	}
	if p.Phase == "LOCAL_GUARD" {
		return Diagnosis{Layer: "POLICY", State: "LOCAL_GUARD_REJECTED"}
	}
	if p.Failure == "TLS_CERTIFICATE_ERROR" {
		return Diagnosis{Layer: "TLS", State: "CERTIFICATE_REJECTED"}
	}
	if p.Failure != "" {
		layer := "OPEN" // RELAY_OR_TCP_OPEN is not proof of a failed origin SYN.
		switch p.Phase {
		case "ORIGIN_TLS":
			layer = "TLS"
		case "ORIGIN_HTTP":
			layer = "HTTP"
		case "ORIGIN_BODY", "ORIGIN_RESPONSE":
			layer = "TRANSFER"
		}
		state := "IO_FAILED"
		switch {
		case p.Detail == "CANCELED":
			state = "CANCELED"
		case p.Detail == "PEER_RESET":
			state = "RESET_OBSERVED"
		case p.Failure == "NETWORK_TIMEOUT" && p.BodyBytes > 0:
			state = "BODY_STALLED_AFTER_PROGRESS"
		case p.Failure == "NETWORK_TIMEOUT":
			state = "TIMEOUT_NO_COMPLETE_RESPONSE"
		case p.Detail == "PEER_CLOSED":
			state = "EOF_OBSERVED"
		}
		return Diagnosis{Layer: layer, State: state}
	}
	if p.Status >= 400 {
		return Diagnosis{Layer: "HTTP", State: "HTTP_DENIED_OR_ERROR"}
	}
	if p.Status >= 200 && p.Status < 300 && p.BodyBytes > 64*1024 {
		return Diagnosis{Layer: "HTTP", State: "PUBLIC_BODY_TRANSFER_VERIFIED"}
	}
	if p.Status > 0 {
		return Diagnosis{Layer: "HTTP", State: "HTTP_CONTROL_ONLY_NOT_BULK"}
	}
	return Diagnosis{Layer: "TLS", State: "NO_HTTP_PROOF"}
}

func DiagnoseStream(reason string, tx, rx uint64, wire *browserproxy.TLSWireEvidence) Diagnosis {
	r := strings.ToUpper(reason)
	if strings.Contains(r, "TLS_ALERT") || strings.Contains(r, "INVALID_HEADER") || wire != nil && (wire.Origin.AlertLevel != 0 || wire.Origin.State == "NON_TLS_OR_INVALID_HEADER") {
		return Diagnosis{Layer: "TLS", State: "ALERT_OR_INVALID_RECORD"}
	}
	if strings.Contains(r, "RST") || strings.Contains(r, "RESET") {
		return Diagnosis{Layer: "TRANSPORT", State: "RESET_OBSERVED"}
	}
	if strings.Contains(r, "CLIENT_INITIATED") || strings.Contains(r, "SMALL_EOF_INCONCLUSIVE") {
		return Diagnosis{Layer: "TRANSPORT", State: "NEUTRAL_CLOSE_NOT_FAILURE"}
	}
	if strings.Contains(r, "MIDSTREAM_STALL") {
		return Diagnosis{Layer: "TRANSFER", State: "UNANSWERED_REQUEST_STALL_NOT_PLAYBACK_PROOF"}
	}
	if strings.Contains(r, "TIMEOUT") || strings.Contains(r, "SILENT") || strings.Contains(r, "BUDGET") {
		layer := "TLS"
		if wire != nil && wire.Origin.ServerHelloComplete {
			layer = "TRANSFER"
		}
		return Diagnosis{Layer: layer, State: "TIMEOUT_OBSERVED"}
	}
	if strings.Contains(r, "EOF") {
		if rx == 0 {
			return Diagnosis{Layer: "TLS", State: "EOF_BEFORE_ORIGIN_REPLY"}
		}
		return Diagnosis{Layer: "TRANSPORT", State: "EOF_AFTER_ORIGIN_REPLY_NOT_STRATEGY_PROOF"}
	}
	if strings.Contains(r, "OPEN_FAILED") || strings.Contains(r, "OPEN_IO_FAILED") {
		return Diagnosis{Layer: "OPEN", State: "OPEN_FAILED_OR_REJECTED"}
	}
	if strings.Contains(r, "FAILED") || strings.Contains(r, "BLOCK") || strings.Contains(r, "ERROR") {
		return Diagnosis{Layer: "TRANSPORT", State: "IO_FAILED_OR_CLOSED"}
	}
	if wire != nil && wire.Origin.ServerHelloComplete {
		if wire.Origin.ApplicationBytes > 0 {
			return Diagnosis{Layer: "TRANSFER", State: "ENCRYPTED_TRANSFER_NOT_PAGE_OR_PLAYBACK_PROOF"}
		}
		return Diagnosis{Layer: "TLS", State: "SERVER_HELLO_ONLY"}
	}
	if tx > 0 && rx == 0 {
		return Diagnosis{Layer: "TLS", State: "WAITING_ORIGIN_BYTES"}
	}
	return Diagnosis{Layer: "TRANSPORT", State: "INSUFFICIENT_EVIDENCE"}
}

// Active layered probes already measure TCP separately. Do not infer SYN loss,
// DNS poisoning or a DPI culprit from timeout/reset alone.
func DiagnoseHost(r HostResult) Diagnosis {
	if r.TCP == "" {
		return Diagnosis{Layer: "OPEN", State: "NOT_MEASURED"}
	}
	if r.TCP != "OK" {
		return Diagnosis{Layer: "TCP", State: "CONNECT_FAILED"}
	}
	if r.RealTLS != "OK" {
		return Diagnosis{Layer: "TLS", State: "HANDSHAKE_FAILED"}
	}
	return DiagnoseProbe(r.HTTP)
}
