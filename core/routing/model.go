// Package routing owns decisions and flow metadata independently of packet capture.
package routing

import (
	"context"
	"net/netip"
	"time"
)

type RouteKind string

const (
	DirectRoute     RouteKind = "DIRECT"
	DirectPlusRoute RouteKind = "DIRECT_PLUS"
	RelayRoute      RouteKind = "RELAY"
)

type Route struct {
	RelayID string
	Kind    RouteKind `json:"kind,omitempty"`
}

func (r Route) Local() bool { return r.RelayID == "" && r.Kind == DirectPlusRoute }
func (r Route) Type() RouteKind {
	if r.RelayID != "" {
		return RelayRoute
	}
	if r.Local() {
		return DirectPlusRoute
	}
	return DirectRoute
}

func (r Route) Direct() bool { return r.RelayID == "" }

type Flow struct {
	OriginDomain  string  `json:"origin_domain,omitempty"`
	OriginService string  `json:"origin_service,omitempty"`
	OriginReason  string  `json:"origin_reason,omitempty"`
	Network       string  `json:"network_fingerprint,omitempty"`
	PinnedPolicy  *Policy `json:"-"`
	// UDPFakePrelude asks the adaptive DIRECT path to send this many fake
	// datagrams before each of the first UDPFakeCutoff real ones (Discord voice).
	UDPFakePrelude, UDPFakeCutoff uint8 `json:"-"`
	Protocol                      string
	Source, Destination           netip.AddrPort
	PID                           uint32
	OwnerBirth                    uint64 `json:"-"`
	ProcessPath, ApplicationID    string
	Route                         Route
	CreatedAt, LastActivity       time.Time
}

// Backend must identify the process before passing its flow to the routing core.
// Stop must remove interception and restore DIRECT networking.
type Backend interface {
	Run(context.Context, func(Flow) Route) error
	Stop() error
}
type Profile struct {
	ID, Name            string
	Executables         []string
	Policy              string
	ProtocolHints       []string
	PortHints           []uint16
	TransportPreference string
}
