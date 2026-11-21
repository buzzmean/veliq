package protocol

func OpenRejection(code byte) string {
	switch code {
	case 2:
		return "relay_destination_denied"
	case 3:
		return "relay_flow_capacity"
	case 4:
		return "upstream_dial_timeout"
	case 5:
		return "upstream_connection_refused"
	case 6:
		return "upstream_dial_failed"
	case 7:
		return "authorization_expired_or_revoked"
	default:
		return "relay_rejected_unspecified"
	}
}
