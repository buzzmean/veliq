package browserproxy

// Only a complete ClientHello (plus optional dummy CCS) can be resent before ANY
// origin response. TLS 1.3 early data and application records are not idempotent.
// This examines plaintext record framing only; it never decrypts application TLS.
func clientHelloFlight(raw []byte) bool {
	handshake := make([]byte, 0, len(raw))
	for len(raw) > 0 {
		if len(raw) < 5 || raw[1] != 3 || raw[2] > 3 {
			return false
		}
		n := int(raw[3])<<8 | int(raw[4])
		if n == 0 || n > len(raw)-5 {
			return false
		}
		switch raw[0] {
		case 22:
			handshake = append(handshake, raw[5:5+n]...)
		case 20:
			if n != 1 || raw[5] != 1 {
				return false
			}
		default:
			return false
		}
		raw = raw[5+n:]
	}
	return len(handshake) >= 4 && handshake[0] == 1 && int(handshake[1])<<16|int(handshake[2])<<8|int(handshake[3]) == len(handshake)-4
}
