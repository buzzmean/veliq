package netdiagnostic

import (
	"golang.org/x/net/dns/dnsmessage"
	"testing"
)

func TestDNSFlagsAndQuestionValidation(t *testing.T) {
	q, e := dnsQuestion("www.youtube.com")
	if e != nil {
		t.Fatal(e)
	}
	var m dnsmessage.Message
	if m.Unpack(q) != nil {
		t.Fatal("query")
	}
	m.Header.Response = true
	m.Header.Authoritative = true
	m.Header.RCode = dnsmessage.RCodeNameError
	b, _ := m.Pack()
	var r DNSResult
	if parseDNS(q, b, &r) != nil || !r.AA || r.Result != "RCodeNameError" || r.AD {
		t.Fatal(r)
	}
	m.Header.ID++
	b, _ = m.Pack()
	if parseDNS(q, b, &r) == nil {
		t.Fatal("mismatch accepted")
	}
	m.Header.ID--
	m.Questions[0].Name, _ = dnsmessage.NewName("discord.com.")
	b, _ = m.Pack()
	if parseDNS(q, b, &r) == nil {
		t.Fatal("foreign question accepted")
	}
}
func TestDNSComparisonDoesNotClaimTamperingFromAA(t *testing.T) {
	rows := []DNSResult{{Result: "RCodeNameError", AA: true, Transport: "udp"}}
	if DNSComparison(rows) != "AA_NXDOMAIN_OBSERVED_NO_ENCRYPTED_POSITIVE_CONTROL" {
		t.Fatal(rows)
	}
	rows = append(rows, DNSResult{Result: "ANSWER", Transport: "dot", Addresses: []string{"192.0.2.1"}})
	if DNSComparison(rows) != "DNS_NEGATIVE_VS_VERIFIED_ENCRYPTED_ANSWER_POSSIBLE_INTERFERENCE" {
		t.Fatal(rows)
	}
}
