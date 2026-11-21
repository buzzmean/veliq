package netdiagnostic

// Authenticated encrypted DNS is a comparison, not proof that the resolver has
// complete current CDN data. AA NXDOMAIN is not itself proof of interception.
func DNSComparison(rows []DNSResult) string {
	negative, encrypted, aa := false, false, false
	for _, r := range rows {
		if r.Result == "RCodeNameError" || r.Result == "SYSTEM_NAME_NOT_FOUND" {
			negative = true
			aa = aa || r.AA
		}
		if (r.Transport == "dot" || r.Transport == "doh") && r.Result == "ANSWER" && len(r.Addresses) > 0 {
			encrypted = true
		}
	}
	if negative && encrypted {
		return "DNS_NEGATIVE_VS_VERIFIED_ENCRYPTED_ANSWER_POSSIBLE_INTERFERENCE"
	}
	if negative && aa {
		return "AA_NXDOMAIN_OBSERVED_NO_ENCRYPTED_POSITIVE_CONTROL"
	}
	if negative {
		return "DNS_NEGATIVE_UNDETERMINED"
	}
	return "DNS_NO_CONFLICT_PROVEN"
}
