// Package localstrategy implements opt-in, process-scoped direct packet transformations.
// It never opens sockets, changes routes, or reads files in the packet path.
package localstrategy

import (
	"errors"
	"net/netip"
	"strings"
)

type DomainSet []string

func domain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) == 0 || len(s) > 253 {
		return "", errors.New("invalid domain")
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("domain must be ASCII/punycode")
			}
		}
	}
	return s, nil
}
func NewDomainSet(all []string) (DomainSet, error) {
	if len(all) > 256 {
		return nil, errors.New("too many domains")
	}
	out := DomainSet{}
	for _, s := range all {
		prefix := ""
		if strings.HasPrefix(s, "*.") {
			prefix = "*."
			s = s[2:]
		}
		d, e := domain(s)
		if e != nil {
			return nil, e
		}
		out = append(out, prefix+d)
	}
	return out, nil
}

// Plain names are exact; *.example.test matches children, not the apex.
func (d DomainSet) Contains(host string) bool {
	h, e := domain(host)
	if e != nil {
		return false
	}
	for _, v := range d {
		if v == h || strings.HasPrefix(v, "*.") && strings.HasSuffix(h, v[1:]) && h != v[2:] {
			return true
		}
	}
	return false
}

type IPSet []netip.Prefix

func NewIPSet(all []string) (IPSet, error) {
	if len(all) > 256 {
		return nil, errors.New("too many CIDRs")
	}
	out := IPSet{}
	for _, s := range all {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, e
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Bits() == 0 {
			return nil, errors.New("global /0 strategies forbidden")
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
func (s IPSet) Contains(a netip.Addr) bool {
	for _, p := range s {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

type ExcludeSet struct {
	Domains DomainSet
	IPs     IPSet
}

func (e ExcludeSet) Contains(host string, a netip.Addr) bool {
	return e.Domains.Contains(host) || e.IPs.Contains(a)
}
