package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	relayPathProbeTimeout = 1500 * time.Millisecond
	relayPathAttempts     = 3
)

type RelayPathChange struct {
	Local          netip.AddrPort
	ValidationTime time.Duration
}

// PathSwitchReady is a caller-defined local admission check run after the peer
// validates the address. It can discard a viable path when policy has changed.
type PathSwitchReady func(change RelayPathChange) bool

// SwitchSameRelayPath validates a bound local UDP path to the existing QUIC peer
// and schedules a switch on that connection. It does not establish a new relay
// session or affect this session's authorization or origin sockets. The caller
// must select the local address independently: validation establishes
// reachability and is not a quality comparison. Require subsequent traffic for
// proof of the switch. This is not invoked by the normal AUTO decision.
func (c *Client) SwitchSameRelayPath(ctx context.Context, local netip.AddrPort, ready PathSwitchReady) (RelayPathChange, error) {
	if err := ctx.Err(); err != nil {
		return RelayPathChange{}, err
	}
	if ready == nil {
		return RelayPathChange{}, errors.New("relay path admission required")
	}
	ip := local.Addr().Unmap()
	if !ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
		return RelayPathChange{}, errors.New("specific unicast client address required")
	}
	if !c.Renewable() || !time.Now().Before(c.Lease().ValidUntil) {
		return RelayPathChange{}, errors.New("live relay authorization lease required")
	}
	if !c.pathMu.TryLock() {
		return RelayPathChange{}, errors.New("relay path change in progress")
	}
	defer c.pathMu.Unlock()
	if c.conn.Context().Err() != nil {
		return RelayPathChange{}, ErrClosed
	}
	if len(c.pathTransports) == 0 {
		return RelayPathChange{}, errors.New("relay session did not negotiate path migration")
	}
	if len(c.pathTransports) >= 1+relayPathAttempts {
		return RelayPathChange{}, errors.New("relay path attempt limit reached")
	}
	peer := c.relayAddr.(*net.UDPAddr).AddrPort().Addr().Unmap()
	if ip.Is4() != peer.Is4() {
		return RelayPathChange{}, errors.New("client address family does not match relay")
	}
	socket, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return RelayPathChange{}, err
	}
	alternate := &quic.Transport{Conn: socket}
	path, err := c.conn.AddPath(alternate)
	if err != nil {
		_ = socket.Close()
		return RelayPathChange{}, err
	}
	// quic-go registers this transport as another connection-ID handler during
	// Probe. Closing the transport then can terminate the current connection,
	// even when validation fails. Retain bounded attempts until the session ends.
	c.pathTransports = append(c.pathTransports, alternate)
	started := time.Now()
	probe, cancel := context.WithTimeout(ctx, relayPathProbeTimeout)
	defer cancel()
	stop := context.AfterFunc(c.conn.Context(), cancel)
	defer stop()
	if err := path.Probe(probe); err != nil {
		_ = path.Close()
		return RelayPathChange{}, err
	}
	change := RelayPathChange{Local: socket.LocalAddr().(*net.UDPAddr).AddrPort(), ValidationTime: time.Since(started)}
	if err := probe.Err(); err != nil {
		_ = path.Close()
		return RelayPathChange{}, err
	}
	if !ready(change) {
		_ = path.Close()
		return RelayPathChange{}, errors.New("validated relay path was not admitted")
	}
	if err := probe.Err(); err != nil {
		_ = path.Close()
		return RelayPathChange{}, err
	}
	if !time.Now().Before(c.Lease().ValidUntil) || c.conn.Context().Err() != nil {
		_ = path.Close()
		return RelayPathChange{}, ErrClosed
	}
	if err := path.Switch(); err != nil {
		_ = path.Close()
		return RelayPathChange{}, err
	}
	return change, nil
}

func (c *Client) closePathTransports() {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	if len(c.pathTransports) == 0 {
		return
	}
	// Close shared QUIC transports only after quic-go removes live handlers.
	<-c.conn.Context().Done()
	for _, transport := range c.pathTransports {
		_ = transport.Close()
		_ = transport.Conn.Close()
	}
	c.pathTransports = nil
}
