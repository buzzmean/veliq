package browserproxy

import "golang.org/x/net/dns/dnsmessage"

// Classification never trusts an unmatched reply or changes DNS wire semantics.
func DNSResponseStatus(query, reply []byte) string {
	hints, err := ValidateDNSResponse(query, reply)
	if err != nil {
		return "DNS_INVALID_RESPONSE"
	}
	var m dnsmessage.Message
	if m.Unpack(reply) != nil {
		return "DNS_INVALID_RESPONSE"
	}
	if m.Truncated {
		return "DNS_TRUNCATED"
	}
	switch m.RCode {
	case dnsmessage.RCodeNameError:
		return "DNS_NXDOMAIN"
	case dnsmessage.RCodeServerFailure:
		return "DNS_SERVFAIL"
	case dnsmessage.RCodeRefused:
		return "DNS_REFUSED"
	case dnsmessage.RCodeSuccess:
		if len(hints) == 0 {
			if len(m.Answers) > 0 {
				return "DNS_RESPONSE_NO_ADDRESS_HINTS"
			}
			return "DNS_NODATA"
		}
		return "DNS_RESPONSE"
	default:
		return "DNS_ERROR_RESPONSE"
	}
}
