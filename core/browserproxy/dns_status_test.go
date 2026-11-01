package browserproxy

import (
	"golang.org/x/net/dns/dnsmessage"
	"testing"
)

func TestDNSStatusValidatesIdentityAndSeparatesNegativeAnswers(t *testing.T) {
	query, reply := wireDNS(t, dnsmessage.TypeA)
	var base dnsmessage.Message
	if err := base.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		rcode dnsmessage.RCode
		tc    bool
		state string
	}{
		{dnsmessage.RCodeSuccess, false, "DNS_NODATA"},
		{dnsmessage.RCodeNameError, false, "DNS_NXDOMAIN"},
		{dnsmessage.RCodeServerFailure, false, "DNS_SERVFAIL"},
		{dnsmessage.RCodeRefused, false, "DNS_REFUSED"},
		{dnsmessage.RCodeFormatError, false, "DNS_ERROR_RESPONSE"},
		{dnsmessage.RCodeSuccess, true, "DNS_TRUNCATED"},
	} {
		m := base
		m.Answers = nil
		m.RCode = tc.rcode
		m.Truncated = tc.tc
		wire, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if got := DNSResponseStatus(query, wire); got != tc.state {
			t.Fatal(got, tc.state)
		}
		m.ID++
		bad, _ := m.Pack()
		if got := DNSResponseStatus(query, bad); got != "DNS_INVALID_RESPONSE" {
			t.Fatal("mismatched negative accepted", got)
		}
	}
	if got := DNSResponseStatus(query, reply); got != "DNS_RESPONSE" {
		t.Fatal(got)
	}
	// A service/alias response can be useful without carrying any A/AAAA hint.
	base.Answers = nil
	alias, _ := dnsmessage.NewName("alias.example.")
	base.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: base.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}}
	aliasWire, _ := base.Pack()
	if got := DNSResponseStatus(query, aliasWire); got != "DNS_RESPONSE_NO_ADDRESS_HINTS" {
		t.Fatal(got)
	}
}
