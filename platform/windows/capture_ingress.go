package windowsplatform

import (
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/localstrategy"
)

// Transport counters cover this backend lifetime, independently of Engine flows
// and the bounded application ledger. No payload or command line is retained.
type CaptureIngressSnapshot struct {
	Scope             string                 `json:"scope"`
	TCPFilter         string                 `json:"tcp_filter"`
	UDPFilter         string                 `json:"udp_filter"`
	SocketFilter      string                 `json:"socket_filter"`
	IPv6Filter        string                 `json:"ipv6_filter"`
	NativeDeferredSYN uint64                 `json:"native_deferred_syn"`
	ReflectedAccepts  uint64                 `json:"reflected_accepts"`
	TCPPackets        uint64                 `json:"tcp_packets"`
	UDP443Packets     uint64                 `json:"udp_443_packets"`
	IPv6Packets       uint64                 `json:"ipv6_packets"`
	SocketEvents      uint64                 `json:"socket_events"`
	UnknownTCPOwner   uint64                 `json:"unknown_tcp_owner"`
	Records           []CaptureIngressRecord `json:"records"`
	Lost              uint64                 `json:"lost"`
}
type CaptureIngressRecord struct {
	Network        string                               `json:"network,omitempty"`
	PolicyRevision string                               `json:"policy_revision,omitempty"`
	QUICOrigin     *localstrategy.QUICOriginObservation `json:"quic_origin,omitempty"`
	At             time.Time                            `json:"at"`
	Stage          string                               `json:"stage"`
	PID            uint32                               `json:"pid"`
	Birth          uint64                               `json:"creation_time"`
	Exe            string                               `json:"exe,omitempty"`
	Source         string                               `json:"source"`
	Destination    string                               `json:"destination"`
	Protocol       string                               `json:"protocol"`
	Profile        string                               `json:"profile_id,omitempty"`
	Decision       string                               `json:"decision"`
	PolicySource   string                               `json:"policy_source,omitempty"`
	OwnerLookup    string                               `json:"owner_lookup"`
	Error          string                               `json:"error,omitempty"`
}
type captureIngress struct {
	tcp, udp443, ipv6, socket, unknown atomic.Uint64
	nativeSYN, accepted                atomic.Uint64
	mu                                 sync.Mutex
	records                            []CaptureIngressRecord
	lost                               uint64
	tcpFilter                          string
}

const captureUDPFilter = "outbound and ip and udp and (!loopback or udp.DstPort == 53) and !impostor"
const captureSocketFilter = "(tcp and event == CONNECT) or (ipv6 and (event == CONNECT or (udp and event == BIND)))"
const captureIPv6Filter = "ipv6 and (tcp or udp) and !loopback and !impostor"

func browserProcess(id ProcessIdentity) bool {
	n := strings.ToLower(path.Base(strings.ReplaceAll(id.Path, `\`, "/")))
	return n == "chrome.exe" || n == "msedge.exe"
}
func ingressDecision(id ProcessIdentity, d Decision, syn, self bool) string {
	switch {
	case self:
		return "OWN_SERVICE_EXCLUDED"
	case id.PID == 0 || id.CreationTime == 0 || id.Path == "":
		return "PROCESS_IDENTITY_UNAVAILABLE"
	case d.Flow.ApplicationID == "":
		return "PROFILE_NOT_MATCHED"
	case !syn:
		return "EXISTING_TCP_PINNED"
	case d.Block:
		return "POLICY_BLOCK"
	case d.Deferred && d.OpenDeferred != nil:
		return "NATIVE_DEFERRED_SYN"
	case d.Deferred:
		return "DOMAIN_DEFERRED_SYN"
	case d.OpenDeferred != nil:
		return "PLANNED_SYN"
	case !d.Route.Direct():
		return "ROUTED_SYN"
	default:
		return "DIRECT_DECISION"
	}
}
func (l *captureIngress) record(stage string, id ProcessIdentity, t Tuple, d Decision, decision, owner, code string) {
	l.recordWithOrigin(stage, id, t, d, decision, owner, code, nil)
}
func (l *captureIngress) recordQUICOrigin(id ProcessIdentity, t Tuple, d Decision, o localstrategy.QUICOriginObservation) {
	l.recordWithOrigin("QUIC_ORIGIN_OBSERVATION", id, t, d, "UDP443_BLOCK", "UDP_OWNER_OR_FLOW", "", &o)
}
func (l *captureIngress) recordWithOrigin(stage string, id ProcessIdentity, t Tuple, d Decision, decision, owner, code string, origin *localstrategy.QUICOriginObservation) {
	// Samples are bounded separately; ordinary game packet processing only uses
	// atomic totals. Keep unknown ownership and browser attribution, not all apps.
	if !browserProcess(id) && id.PID != 0 && code == "" {
		return
	}
	if len(id.Path) > 2048 {
		id.Path = id.Path[:2048]
	}
	v := CaptureIngressRecord{QUICOrigin: origin, At: time.Now(), Stage: stage, PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Source: t.Source.String(), Destination: t.Destination.String(), Protocol: t.Protocol, Profile: d.Flow.ApplicationID, Decision: decision, PolicySource: d.Policy.Source, OwnerLookup: owner, Error: code}
	if origin != nil {
		v.Network = d.Network
		v.PolicyRevision = d.Revision
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	const limit = 24
	if len(l.records) == limit {
		copy(l.records, l.records[1:])
		l.records = l.records[:limit-1]
		l.lost++
	}
	l.records = append(l.records, v)
}
func (l *captureIngress) snapshot(pid uint32) CaptureIngressSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := CaptureIngressSnapshot{Scope: "BACKEND_LIFETIME; totals global; records bounded metadata", TCPFilter: l.tcpFilter, UDPFilter: captureUDPFilter, SocketFilter: captureSocketFilter, IPv6Filter: captureIPv6Filter, NativeDeferredSYN: l.nativeSYN.Load(), ReflectedAccepts: l.accepted.Load(), TCPPackets: l.tcp.Load(), UDP443Packets: l.udp443.Load(), IPv6Packets: l.ipv6.Load(), SocketEvents: l.socket.Load(), UnknownTCPOwner: l.unknown.Load(), Records: []CaptureIngressRecord{}, Lost: l.lost}
	for _, r := range l.records {
		if pid == 0 || r.PID == pid {
			if r.QUICOrigin != nil {
				v := *r.QUICOrigin
				r.QUICOrigin = &v
			}
			out.Records = append(out.Records, r)
		}
	}
	return out
}
