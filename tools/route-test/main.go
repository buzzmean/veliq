// route-test uses application sockets and the existing ticket-authenticated relay.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

type options struct {
	relay, target, controlPlane, relayID, state, trust, ca, cpCA, echoToken, tcpTarget, enrollToken, report string
	count                                                                                                   int
	interval, timeout                                                                                       time.Duration
	smoke                                                                                                   bool
	upgrade                                                                                                 bool
	expectedEgress                                                                                          string
}

func main() { os.Exit(command(os.Args[1:])) }
func command(args []string) int {
	fs := flag.NewFlagSet("neexitlag-route-test", flag.ContinueOnError)
	o := options{}
	fs.StringVar(&o.relay, "relay", "", "configured relay IPv4:UDP port")
	fs.StringVar(&o.target, "target", "", "authenticated UDP echo IPv4:port")
	fs.StringVar(&o.controlPlane, "control-plane", "", "existing HTTPS control plane")
	fs.StringVar(&o.relayID, "relay-id", "VPS-01", "signed ticket audience")
	fs.StringVar(&o.state, "state", ".e2e/bundle/windows/device", "protected enrolled identity.json/device.pem directory")
	fs.StringVar(&o.trust, "trust", ".e2e/bundle/windows/trust/trust.json", "out-of-band signing trust")
	fs.StringVar(&o.ca, "ca", ".e2e/bundle/windows/trust/ca.pem", "relay CA")
	fs.StringVar(&o.cpCA, "cp-ca", ".e2e/bundle/windows/trust/cp-ca.pem", "control-plane CA")
	fs.StringVar(&o.echoToken, "echo-token-file", ".e2e/bundle/windows/echo.token", "private authenticated echo token file")
	fs.StringVar(&o.enrollToken, "enroll-token-file", "", "optional private bootstrap token file; never copied to relay")
	fs.StringVar(&o.tcpTarget, "tcp-target", "", "optional authenticated TCP echo IPv4:port")
	fs.StringVar(&o.report, "report", "", "JSON report path (contains measured observations, no credentials)")
	fs.IntVar(&o.count, "count", 100, "measured UDP probes per route, 30..200")
	fs.DurationVar(&o.interval, "interval", 200*time.Millisecond, "probe spacing, 20ms..1s")
	fs.DurationVar(&o.timeout, "timeout", time.Second, "per-probe and connection timeout, 100ms..10s")
	fs.BoolVar(&o.upgrade, "upgrade-check", false, "verify real /3 + legacy /2, two immediate same-session renewals, mTLS/replay and unchanged TCP/UDP sockets; no enrollment")
	fs.StringVar(&o.expectedEgress, "expected-egress", "", "required authenticated echo source for --upgrade-check")
	fs.BoolVar(&o.smoke, "smoke", false, "also prove TCP, invalid credentials and real ticket expiry (normally 2 minutes; bounded to 5 minutes)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || o.count < 30 || o.count > 200 || o.interval < 20*time.Millisecond || o.interval > time.Second || o.timeout < 100*time.Millisecond || o.timeout > 10*time.Second {
		fmt.Fprintln(os.Stderr, "invalid bounded benchmark parameters")
		return 2
	}
	for _, value := range []string{o.target, o.relay} {
		addr, err := netip.ParseAddrPort(value)
		if err != nil || !addr.Addr().Is4() || addr.Port() == 0 {
			fmt.Fprintln(os.Stderr, "relay and target must be explicit literal IPv4:port")
			return 2
		}
	}
	cpURL, cpErr := url.Parse(o.controlPlane)
	if cpErr != nil || cpURL.Scheme != "https" || cpURL.Host == "" || cpURL.User != nil {
		fmt.Fprintln(os.Stderr, "--control-plane HTTPS endpoint required; relay is not an open proxy")
		return 2
	}
	if o.smoke && o.tcpTarget == "" {
		o.tcpTarget = o.target
	}
	if o.tcpTarget != "" {
		dst, err := netip.ParseAddrPort(o.tcpTarget)
		if err != nil || !dst.Addr().Is4() || dst.Port() == 0 {
			fmt.Fprintln(os.Stderr, "invalid TCP target")
			return 2
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if o.upgrade {
		return upgradeCommand(ctx, o)
	}
	result, err := run(ctx, o)
	printReport(result)
	if o.report != "" {
		raw, _ := json.MarshalIndent(result, "", "  ")
		if e := os.MkdirAll(filepath.Dir(o.report), 0700); e != nil {
			fmt.Fprintln(os.Stderr, "report directory unavailable")
			return 1
		}
		if e := os.WriteFile(o.report, raw, 0600); e != nil {
			fmt.Fprintln(os.Stderr, "report write failed")
			return 1
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
