// Read-only probes for already used public controls; no credentials/installation/VPS access.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/buzzmean/neexitlag/core/netdiagnostic"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	host := flag.String("host", "www.youtube.com", "public control hostname")
	resolvers := flag.String("resolvers", "8.8.8.8,1.1.1.1,9.9.9.9,77.88.8.8", "DNS IPv4s")
	flag.Parse()
	paths := map[string]string{"www.youtube.com": "/", "discord.com": "/", "i.ytimg.com": "/vi/aqz-KE-bpKQ/maxresdefault.jpg"}
	path, ok := paths[*host]
	if !ok {
		fmt.Fprintln(os.Stderr, "PUBLIC_PROBE_HOST_NOT_ALLOWLISTED")
		os.Exit(2)
	}
	ips := strings.Split(*resolvers, ",")
	if len(ips) > 8 {
		fmt.Fprintln(os.Stderr, "DNS_RESOLVER_LIMIT_8")
		os.Exit(2)
	}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			fmt.Fprintln(os.Stderr, "DNS_RESOLVER_IP_REQUIRED")
			os.Exit(2)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	enc := json.NewEncoder(os.Stdout)
	emit := func(kind string, v any) { _ = enc.Encode(map[string]any{"kind": kind, "evidence": v}) }
	addresses := []string{}
	dnsRows := []netdiagnostic.DNSResult{}
	seen := map[string]bool{}
	add := func(r netdiagnostic.DNSResult) {
		emit("dns", r)
		dnsRows = append(dnsRows, r)
		for _, ip := range r.Addresses {
			if !seen[ip] {
				seen[ip] = true
				addresses = append(addresses, ip)
			}
		}
	}
	sysctx, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
	add(netdiagnostic.DNS(sysctx, *host, "system", "system"))
	stop()
	for _, ip := range ips {
		for _, mode := range []string{"udp", "tcp"} {
			add(netdiagnostic.DNS(ctx, *host, ip, mode))
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "94.140.14.14"} {
		add(netdiagnostic.DNS(ctx, *host, ip, "dot"))
	}
	add(netdiagnostic.DNS(ctx, *host, "8.8.8.8", "doh"))
	emit("dns_comparison", netdiagnostic.DNSComparison(dnsRows))
	checked := 0
	for _, ip := range addresses {
		if net.ParseIP(ip).To4() == nil {
			continue
		}
		emit("host", netdiagnostic.Host(ctx, *host, ip, path))
		checked++
		if checked >= 2 {
			break
		}
	}
	emit("limits", map[string]string{"verdict": "NXDOMAIN/aa/different answers alone do not prove tampering; TCP connect failure does not prove SYN drop; verified DoT/DoH answers are comparisons; no tokens, redirects followed or TLS bypass", "capture": "diagnostic process follows its own routes; not proof of browser/launcher path"})
}
