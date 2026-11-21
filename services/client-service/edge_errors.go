package clientservice

import (
	"errors"
	"net"
	"os"
	"strings"
)

// Errors exported to IPC/status are a small allowlist of codes, never arbitrary
// OS paths, registry content, helper output, identity or credentials.
func edgeErrorCode(err error) string {
	if os.IsPermission(err) {
		return "EDGE_POLICY_ACCESS_DENIED"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "EDGE_TIMEOUT"
	}
	text := err.Error()
	for _, code := range strings.Fields(text) {
		if edgeGUIFailureAllowed("edge.prepare", code) {
			return code
		}
	}
	switch {
	case strings.Contains(text, "another owner"), strings.Contains(text, "foreign"), strings.Contains(text, "machine-managed"):
		return "EDGE_POLICY_MANAGED"
	case strings.Contains(text, "readiness not observed"):
		return "EDGE_READINESS_NOT_OBSERVED"
	case strings.Contains(text, "SID"):
		return "EDGE_OWNER_SID_REQUIRED"
	case strings.Contains(text, "DIRECT/AUTO"):
		return "EDGE_PROFILE_MODE_INVALID"
	case strings.Contains(text, "profile required"):
		return "EDGE_PROFILE_NOT_FOUND"
	case strings.Contains(text, "Automatic routing"):
		return "EDGE_AUTOMATIC_DISABLED"
	case strings.Contains(text, "proof expired"):
		return "EDGE_READINESS_EXPIRED"
	case strings.Contains(text, "prepare Edge"):
		return "EDGE_PREPARE_REQUIRED"
	case strings.Contains(text, "another Edge"):
		return "EDGE_OTHER_PROFILE_ACTIVE"
	case strings.Contains(text, "endpoint"), strings.Contains(text, "configuration"):
		return "EDGE_CONFIGURATION_INVALID"
	case strings.Contains(text, "bind"), strings.Contains(text, "address already in use"):
		return "EDGE_LISTENER_BIND_FAILED"
	default:
		return "EDGE_OPERATION_FAILED"
	}
}
func edgeGUIFailureAllowed(phase, code string) bool {
	phases := map[string]bool{"edge.prepare": true, "edge.policy": true, "edge.confirm": true, "edge.recovery": true, "edge.browser_probe": true, "profile.set": true, "optimize": true, "edge.launch": true}
	codes := map[string]bool{"EDGE_IPC_UNSUPPORTED": true, "EDGE_IPC_ACCESS_DENIED": true, "EDGE_GUARD_STATE_WRITE_FAILED": true, "EDGE_POLICY_ACCESS_DENIED": true, "EDGE_POLICY_MANAGED": true, "EDGE_OWNER_SID_REQUIRED": true, "EDGE_PROFILE_MODE_INVALID": true, "EDGE_PROFILE_NOT_FOUND": true, "EDGE_AUTOMATIC_DISABLED": true, "EDGE_READINESS_NOT_OBSERVED": true, "EDGE_READINESS_EXPIRED": true, "EDGE_PREPARE_REQUIRED": true, "EDGE_OTHER_PROFILE_ACTIVE": true, "EDGE_CONFIGURATION_INVALID": true, "EDGE_LISTENER_BIND_FAILED": true, "EDGE_OPERATION_FAILED": true, "EDGE_TIMEOUT": true, "EDGE_RECOVERY_FAILED": true, "EDGE_BROWSER_POLICY_NOT_OBSERVED": true, "EDGE_LAUNCH_FAILED": true, "EDGE_SERVICE_UNAVAILABLE": true}
	return phases[phase] && codes[code]
}
