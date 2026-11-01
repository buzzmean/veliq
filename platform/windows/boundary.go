// Package windowsplatform isolates Windows identity and capture from the portable core.
package windowsplatform

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("Windows capture backend unavailable on this platform")

type Tuple struct {
	Protocol            string
	Source, Destination netip.AddrPort
}
type ProcessIdentity = profiles.Identity
type Capabilities struct {
	IPv4        bool `json:"ipv4"`
	UDP         bool `json:"udp"`
	TCP         bool `json:"tcp"`
	IPv6        bool `json:"ipv6"`
	Transparent bool `json:"transparent"`
}
type CaptureStatus struct {
	Backend      string       `json:"backend"`
	Ready        bool         `json:"ready"`
	Error        string       `json:"error,omitempty"`
	Capabilities Capabilities `json:"capabilities"`
}

// TCPPolicyReporter is evidence from a finite pre-ServerHello opener. It never
// authorizes a kernel reroute of an established application TLS stream.
type TCPPolicyReporter interface {
	CurrentTCPPolicy() (flowpolicy.Result, bool)
}

type Decision struct {
	// Queue only an owned probe; this callback never changes browser routing.
	QUICProbe func(QUICProbeTrigger)

	OriginHintOnly bool // Domain is routing metadata; do not treat it as authenticated SNI.
	// Selected browser DNS only; no DNS/53 packet is relayed.
	DNSExchange func(context.Context, []byte) ([]byte, error)

	GameUDP     *gameudp.Engine
	GameRelayID string
	// Native browser planning runs only in the bounded deferred worker, never
	// under the packet-loop lock. Existing streams keep their original decision.
	NewConnectionsOnly bool
	OpenDeferred       func(context.Context, Decision, string) (net.Conn, Decision, error)
	// OriginDomain comes from validated CONNECT or this flow's unambiguous
	// ClientHello SNI/HTTP Host; native DNS hints are separately labelled in diagnostics.
	OuterSNI        string // ECH outer metadata; never authenticated inner origin.
	OriginDomain    string
	Revision        string
	Policy          flowpolicy.Result
	Group, Network  string
	ProbeDirect     bool
	Deferred        bool
	ResolveDomain   func(string) Decision
	LocalStrategyID string
	Local           *localstrategy.LocalStrategyEngine
	Flow            routing.Flow
	Route           routing.Route
	Block           bool
	BlockOnFailure  bool
}
type Classifier func(ProcessIdentity, Tuple) Decision
type WindowsCaptureBackend interface {
	Start(context.Context, Classifier) error
	Stop() error
	Status() CaptureStatus
}
type Discovery interface {
	Lookup(uint32) (ProcessIdentity, error)
	List() ([]ProcessIdentity, error)
}
type Association struct {
	Identity ProcessIdentity
	Tuple    Tuple
	Endpoint uint64
}
type FlowAssociations struct {
	mu       sync.RWMutex
	items    map[Tuple]Association
	limit    int
	seen     map[Tuple]time.Time
	gameSeen map[Tuple]bool
}

func NewAssociations(limit int) *FlowAssociations {
	if limit <= 0 {
		limit = 8192
	}
	return &FlowAssociations{items: make(map[Tuple]Association), limit: limit, seen: map[Tuple]time.Time{}, gameSeen: map[Tuple]bool{}}
}
func (a *FlowAssociations) Put(v Association) bool {
	if v.Identity.PID == 0 || v.Identity.CreationTime == 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.items[v.Tuple]; !ok && len(a.items) >= a.limit {
		return false
	}
	if old, ok := a.items[v.Tuple]; ok {
		if old.Identity.PID != v.Identity.PID || old.Identity.CreationTime != v.Identity.CreationTime || (v.Endpoint != 0 && old.Endpoint != v.Endpoint) {
			delete(a.gameSeen, v.Tuple)
		}
		if v.Endpoint == 0 && old.Identity == v.Identity {
			v.Endpoint = old.Endpoint
		}
	}
	a.items[v.Tuple] = v
	a.seen[v.Tuple] = time.Now()
	return true
}
func (a *FlowAssociations) Delete(t Tuple, endpoint uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if old, ok := a.items[t]; ok && old.Endpoint == endpoint {
		delete(a.items, t)
		delete(a.seen, t)
		delete(a.gameSeen, t)
	}
}
func (a *FlowAssociations) Get(t Tuple, current ProcessIdentity) (Association, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v, ok := a.items[t]
	return v, ok && v.Identity.PID == current.PID && v.Identity.CreationTime == current.CreationTime && v.Identity.Path == current.Path
}

type WFPBackend struct{}

func (*WFPBackend) Start(context.Context, Classifier) error {
	return errors.New("WFP callout driver is not installed; signed driver and WDK implementation required")
}
func (*WFPBackend) Stop() error { return nil }
func (*WFPBackend) Status() CaptureStatus {
	return CaptureStatus{Backend: "WFP", Error: "WFP callout driver not implemented; networking remains DIRECT"}
}

func (a *FlowAssociations) Touch(t Tuple) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.items[t]; ok {
		a.seen[t] = time.Now()
	}
}
func (a *FlowAssociations) Cleanup(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for t, at := range a.seen {
		if now.Sub(at) > 2*time.Minute {
			delete(a.items, t)
			delete(a.seen, t)
			delete(a.gameSeen, t)
		}
	}
}

// MarkGameFirstFlight consumes the first-flight proof once per native flow.
// The mark outlives the 60s packet cache; idle tuples cannot reset the cutoff.
func (a *FlowAssociations) MarkGameFirstFlight(t Tuple, id ProcessIdentity) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.items[t]
	if !ok || v.Endpoint == 0 || v.Identity.PID != id.PID || v.Identity.CreationTime != id.CreationTime || a.gameSeen[t] {
		return false
	}
	a.gameSeen[t] = true
	return true
}
