//go:build windows

package windowsplatform

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/localstrategy"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"net"
	"net/netip"
)

func LookupTCPPeer(source, destination netip.AddrPort) (ProcessIdentity, error) {
	pid, err := resolveTCPOwner(Tuple{Protocol: "tcp", Source: source, Destination: destination})
	if err != nil {
		return ProcessIdentity{}, err
	}
	return NewDiscovery().Lookup(pid)
}

// OpenBrowserLocalTCP delegates ONLY this exact service-created upstream tuple
// to the existing WinDivert DIRECT+ implementation under its Chrome identity.
func (b *WinDivertBackend) OpenBrowserLocalTCP(ctx context.Context, id ProcessIdentity, source, dest netip.AddrPort, d Decision) (net.Conn, error) {
	if !dest.Addr().Is4() || d.Local == nil || !d.Route.Local() {
		return nil, errors.New("native browser local IPv4 strategy unavailable")
	}
	b.mu.Lock()
	tcp := b.tcp
	ready := b.status.Ready
	b.mu.Unlock()
	if tcp == nil || !ready {
		return nil, ErrUnavailable
	}
	// UDP connect selects an interface address without sending a datagram.
	selector, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dest))
	if err != nil {
		return nil, err
	}
	bind := selector.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	selector.Close()
	tuple := Tuple{Protocol: "tcp", Source: source, Destination: dest}
	b.evidence.BeginFlow(id, tuple)
	b.evidence.RecordDomain(id, tuple, d.OriginDomain)
	b.evidence.RecordInitialPolicy(id, tuple, d)
	e := &tcpEntry{identity: id, tuple: tuple, decision: d}
	return tcp.dialLocalStrategyFrom(ctx, e, d, bind)
}

// OpenBrowserNativeTCP admits only this reserved service socket into native
// capture OPEN worker. The owner, immutable plan and fail-closed callback are
// supplied by the authenticated CONNECT front end, never by a packet/DNS guess.
func (b *WinDivertBackend) OpenBrowserNativeTCP(ctx context.Context, id ProcessIdentity, source, dest netip.AddrPort, d Decision) (net.Conn, error) {
	if !dest.Addr().Is4() || d.Deferred || d.ResolveDomain != nil || d.OpenDeferred == nil || d.OriginDomain == "" || !d.BlockOnFailure || !d.NewConnectionsOnly || !IsCurrent(id) {
		return nil, errors.New("NATIVE_PAC_DELEGATION_INVALID")
	}
	b.mu.Lock()
	tcp, ready := b.tcp, b.status.Ready
	b.mu.Unlock()
	if tcp == nil || !ready {
		return nil, ErrUnavailable
	}
	selector, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(b.nativeDelegationDestination(dest)))
	if err != nil {
		return nil, err
	}
	bind := selector.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	selector.Close()
	tuple := Tuple{Protocol: "tcp", Source: source, Destination: b.nativeDelegationDestination(dest)}
	b.evidence.BeginFlow(id, tuple)
	b.evidence.RecordDomain(id, tuple, d.OriginDomain)
	b.evidence.RecordInitialPolicy(id, tuple, d)
	e := &tcpEntry{identity: id, tuple: tuple, decision: d}
	return tcp.dialDelegatedFrom(ctx, e, d, bind, true)
}

func (b *WinDivertBackend) BrowserTransformApplied(id ProcessIdentity, source, dest netip.AddrPort) bool {
	ev, err := b.evidence.SnapshotQuery(EvidenceQuery{PID: id.PID, CreationTime: id.CreationTime, Source: source.String(), Destination: dest.String()}, nil)
	if err != nil || ev.Truncated || ev.EvidenceLost {
		return false
	}
	for _, f := range ev.Flows {
		if f.Counters.DirectPlus > 0 && f.Counters.DirectPlusBytes > 0 {
			return true
		}
	}
	return false
}

func (b *WinDivertBackend) BrowserLocalInspection(id ProcessIdentity, source, dest netip.AddrPort) *localstrategy.Inspection {
	if b.evidence == nil {
		return nil
	}
	ev, err := b.evidence.SnapshotQuery(EvidenceQuery{PID: id.PID, CreationTime: id.CreationTime, Source: source.String(), Destination: dest.String()}, nil)
	if err != nil || ev.Truncated || ev.EvidenceLost {
		return nil
	}
	for _, f := range ev.Flows {
		if f.LocalInspection != nil {
			v := *f.LocalInspection
			if f.LocalTCP != nil {
				v.TCPPackets = *f.LocalTCP
			}
			v.SentPackets = append([]localstrategy.SentPacket(nil), v.SentPackets...)
			return &v
		}
	}
	return nil
}

func ProcessUserSID(id ProcessIdentity) (string, error) {
	if !IsCurrent(id) {
		return "", errors.New("process identity changed")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, id.PID)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// Validate the actual installation owner's policy before arming native Chrome
// AUTO. A temporary recovery PAC is not an online origin-routing contract.
func ChromeProxyPolicyActive(sid, expected string) bool {
	if expected == "" || len(expected) > 128*1024 {
		return false
	}
	if _, err := windows.StringToSid(sid); err != nil {
		return false
	}
	path := `Software\Policies\Google\Chrome`
	if machine, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE); err == nil {
		defer machine.Close()
		for _, name := range []string{"ProxySettings", "ProxyMode", "ProxyPacUrl", "ProxyServer"} {
			if _, _, err := machine.GetValue(name, nil); err == nil || errors.Is(err, windows.ERROR_MORE_DATA) {
				return false
			}
		}
	}
	key, err := registry.OpenKey(registry.USERS, sid+`\`+path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	raw, _, err := key.GetStringValue("ProxySettings")
	if err != nil || len(raw) > 256*1024 {
		return false
	}
	var policy struct {
		Mode      string `json:"ProxyMode"`
		URL       string `json:"ProxyPacUrl"`
		Mandatory bool   `json:"ProxyPacMandatory"`
	}
	if json.Unmarshal([]byte(raw), &policy) != nil {
		return false
	}
	return policy.Mode == "pac_script" && policy.Mandatory && policy.URL == expected
}

// Windows loopback is outbound-only at WinDivert NETWORK. The isolated driver
// fixture reserves a TEST-NET destination for the intercepted SYN, while the
// immutable callback still opens its real local HTTPS origin. No production
// caller can enable testBrowserLoopback (the setter is in a _test.go file).
func (b *WinDivertBackend) nativeDelegationDestination(dest netip.AddrPort) netip.AddrPort {
	if b.testBrowserLoopback && dest.Addr().IsLoopback() {
		return netip.AddrPortFrom(netip.MustParseAddr("192.0.2.254"), dest.Port())
	}
	return dest
}
