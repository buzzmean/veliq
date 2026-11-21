package clientservice

import (
	"strings"
)

// Never return raw filesystem/IPC/owner/nonce details in the shareable status.
func chromeReadinessError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	switch {
	case message == "CHROME_LISTENER_BIND_FAILED":
		return "CHROME_LISTENER_BIND_FAILED"
	case strings.Contains(message, "readiness not observed"), strings.Contains(message, "proof expired/changed"):
		return "CHROME_READINESS_NOT_OBSERVED"
	case strings.Contains(message, "PAC not installed"):
		return "CHROME_POLICY_NOT_OWNED"
	default:
		return "CHROME_PREPARE_FAILED"
	}
}
