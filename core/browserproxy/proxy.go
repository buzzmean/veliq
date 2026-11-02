// Package browserproxy provides an owner-authorized HTTP CONNECT transport.
// The service supplies application routing; TLS stays end-to-end without request
// replay. Windows configuration is managed outside this package.
package browserproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"golang.org/x/net/idna"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Stable, bounded error classes. Never export arbitrary OS/HTTP error text,
// headers, URLs or credentials in diagnostics.
var (
	ErrOwnerLookup  = errors.New("TCP_OWNER_LOOKUP_FAILED")
	ErrOwnerToken   = errors.New("OWNER_TOKEN_QUERY_FAILED")
	ErrOwnerSID     = errors.New("OWNER_SID_MISMATCH")
	ErrOwnerProfile = errors.New("OWNER_PROFILE_MISMATCH")
	ErrOriginDNS    = errors.New("ORIGIN_DNS_FAILED")
)

type Owner struct {
	PID     uint32 `json:"pid"`
	Birth   uint64 `json:"creation_time"`
	Exe     string `json:"exe"`
	Profile string `json:"profile_id"`
}
type Request struct {
	HintOnly        bool // Native DNS/outer metadata, never exact CONNECT/SNI authority.
	OriginAmbiguous bool
	Owner           Owner
	Source          netip.AddrPort
	Host            string
	Port            uint16
	Secure          bool
	Ingress         string // PAC_CONNECT, PAC_RECOVERY or NATIVE_TCP; never supplied by HTTP headers.
}
type Trial struct {
	Destination      string `json:"destination,omitempty"`
	Phase            string `json:"phase,omitempty"`
	Detail           string `json:"detail,omitempty"`
	ALPN             string `json:"alpn,omitempty"`
	TLSVersion       uint16 `json:"tls_version,omitempty"`
	Route            string `json:"route"`
	Outcome          string `json:"outcome"`
	HTTPStatus       int    `json:"http_status"`
	TransformApplied bool   `json:"transform_applied"`
	DurationMS       int64  `json:"duration_ms"`
}
type Plan struct {
	FirstFlightManaged bool `json:"-"` // Route ladder owns bounded pre-ServerHello retries.
	// Set only by native planner when no protected DNS/outer association exists.
	OrdinaryCapacityDirect bool `json:"-"`

	OriginPrior         []OriginAttempt    `json:"-"`
	OriginNegativeSkips int                `json:"-"`
	RelayCandidates     []netip.AddrPort   `json:"-"`
	DirectIndex         int                `json:"direct_address_slot,omitempty"`
	DirectCandidates    []netip.AddrPort   `json:"direct_candidates,omitempty"`
	DirectDeadline      time.Time          `json:"-"`
	DirectAttempts      int                `json:"direct_attempts,omitempty"`
	DNSRecovery         *DNSRecoveryResult `json:"dns_recovery,omitempty"`
	Trials              []Trial            `json:"trials,omitempty"`
	Network             string             `json:"network"`
	Enabled             bool               `json:"optimizing"`
	Policy              flowpolicy.Result  `json:"policy"`
	Destination         netip.AddrPort     `json:"destination"`
	Probe               string             `json:"probe"`
	HTTPStatus          int                `json:"http_status,omitempty"`
}
type Record struct {
	planReporter       PlanReporter
	Origin             *OriginReport `json:"origin_attempts,omitempty"`
	originReporter     OriginReporter
	TLS                *TLSWireEvidence `json:"tls_wire,omitempty"`
	tlsWire            *TLSWireObserver
	NoReplyReason      string    `json:"-"`
	RequestPayloadSeen bool      `json:"-"`
	OriginPayloadSeen  bool      `json:"-"`
	AcceptedAt         time.Time `json:"-"`
	FirstByteMode      string    `json:"-"`
	FirstByteMS        float64   `json:"-"`
	PlanDurationMS     int64     `json:"plan_duration_ms"`
	OpenDurationMS     int64     `json:"open_duration_ms"`
	EvidenceSource     string    `json:"evidence_source,omitempty"`
	OpenFailure        string    `json:"open_failure,omitempty"`
	DirectPlusApplied  bool      `json:"direct_plus_applied"`
	ID                 uint64    `json:"id"`
	Owner              Owner     `json:"owner"`
	Domain             string    `json:"domain"`
	Port               uint16    `json:"port"`
	Source             string    `json:"source"`
	Plan               Plan      `json:"plan"`
	Started            time.Time `json:"started"`
	Active             bool      `json:"active"`
	Result             string    `json:"result"`
	Sent               uint64    `json:"sent_bytes"`
	Received           uint64    `json:"received_bytes"`
	// StallRetried: the DIRECT origin stayed silent after the ClientHello and the tunnel
	// was transparently moved to the relay (Plan then shows the relay policy).
	StallRetried bool `json:"stall_retried_via_relay,omitempty"`
}
type Snapshot struct {
	ProcessRole        string            `json:"process_role"`
	ProcessID          int               `json:"process_id"`
	LastActivity       time.Time         `json:"last_activity"`
	ActiveConnections  int               `json:"active_connections"`
	FirstByteMetrics   []FirstByteMetric `json:"first_byte_metrics,omitempty"`
	FirstByteLost      uint64            `json:"first_byte_metrics_lost,omitempty"`
	Path               string            `json:"path"`
	PathMetrics        []PathMetrics     `json:"path_metrics"`
	MetricsLost        uint64            `json:"metrics_lost"`
	FailureDetails     []FailureSummary  `json:"failure_details"`
	FailureDetailsLost uint64            `json:"failure_details_lost"`
	RecoveryAddress    string            `json:"recovery_address,omitempty"`
	PolicyReady        bool              `json:"policy_ready"`
	ReadyProfiles      []string          `json:"ready_profiles"`
	Failures           map[string]uint64 `json:"failures"`
	Truncated          bool              `json:"truncated"`
	Listening          bool              `json:"listening"`
	Address            string            `json:"address"`
	Lost               uint64            `json:"lost"`
	Records            []Record          `json:"records"`
}
type Config struct {
	TransportCheck func() (target, token string)

	// Production enables this: TLS early/application data must never be replayed.
	RequireClientHelloReplay bool
	MetadataToken            string
	AuthorizeMetadata        func(context.Context, netip.AddrPort, netip.AddrPort) error
	Metadata                 func() Snapshot
	OpenPlan                 func(context.Context, Request, Plan) (net.Conn, Plan, error)
	Address                  string // Empty allocates a port; otherwise fixed loopback only.
	AuthorizeForwarded       func(context.Context, netip.AddrPort, netip.AddrPort, netip.AddrPort, netip.AddrPort) (Owner, error)
	TransformApplied         func(Request, Plan) bool
	// OnStall, when set, is asked for a relay connection when an ordinary DIRECT port-443
	// tunnel gets no answer from the origin after the browser's first bytes. It is called at
	// most once per tunnel; on error the tunnel is closed (never retried over DIRECT).
	OnStall func(context.Context, Request, Plan) (net.Conn, Plan, error)
	// OnDirectAnswered is called once when such a DIRECT tunnel receives its first byte
	// from the origin. This is progress only: a TLS alert/byte does not prove HTTPS.
	OnDirectAnswered func(Request, Plan)
	// StallTimeout is the silence after the first client bytes that counts as a stall
	// (default DefaultStallTimeout).
	StallTimeout time.Duration
	Authorize    func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error)
	Plan         func(context.Context, Request) (Plan, error)
	Open         func(context.Context, Request, Plan) (net.Conn, error)
}
type Server struct {
	firstBytes         firstByteLedger
	started            time.Time
	lastActivity       time.Time
	paths              map[string]PathMetrics
	metricsLost        uint64
	failureDetails     map[string]FailureSummary
	failureDetailsLost uint64
	cfg                Config
	l                  net.Listener
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	slots              chan struct{}
	mu                 sync.Mutex
	next, lost         uint64
	failures           map[string]uint64
	records            map[uint64]Record
	conns              map[net.Conn]bool
	closed             bool
	challenges         map[string]healthChallenge
	confirmed          map[string]bool
	verified           map[string]string
}

func Listen(parent context.Context, cfg Config) (*Server, error) {
	if cfg.Authorize == nil || cfg.Plan == nil || cfg.Open == nil && cfg.OpenPlan == nil {
		return nil, errors.New("browser transport callbacks required")
	}
	address := cfg.Address
	if address == "" {
		address = "127.0.0.1:0"
	}
	h, _, parseErr := net.SplitHostPort(address)
	if parseErr != nil || h != "127.0.0.1" {
		return nil, errors.New("browser transport must bind loopback")
	}
	l, e := net.Listen("tcp4", address)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{started: time.Now(), lastActivity: time.Now(), cfg: cfg, l: l, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 256), challenges: map[string]healthChallenge{}, confirmed: map[string]bool{}, verified: map[string]string{}, failures: map[string]uint64{}, records: map[uint64]Record{}, conns: map[net.Conn]bool{}}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}
func (s *Server) Address() string { return s.l.Addr().String() }
func (s *Server) CloseConnections() {
	s.mu.Lock()
	all := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		all = append(all, c)
	}
	s.mu.Unlock()
	for _, c := range all {
		c.Close()
	}
}
func (s *Server) Close() {
	s.cancel()
	s.l.Close()
	s.CloseConnections()
	s.wg.Wait()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}
func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	failures := make(map[string]uint64, len(s.failures))
	for k, v := range s.failures {
		failures[k] = v
	}
	ready := []string{}
	for profile := range s.confirmed {
		ready = append(ready, profile)
	}
	out := Snapshot{ProcessRole: "LOCAL_BROWSER_PROXY", ProcessID: os.Getpid(), LastActivity: s.lastActivity, ActiveConnections: len(s.conns), Path: "PAC_CONNECT", PathMetrics: []PathMetrics{}, FailureDetails: []FailureSummary{}, MetricsLost: s.metricsLost, FailureDetailsLost: s.failureDetailsLost, ReadyProfiles: ready, Failures: failures, Listening: !s.closed && s.ctx.Err() == nil, Address: s.Address(), Lost: s.lost, Records: make([]Record, 0, len(s.records))}
	out.FirstByteMetrics, out.FirstByteLost = s.firstBytes.snapshot()
	for _, p := range s.paths {
		out.PathMetrics = append(out.PathMetrics, p)
	}
	for _, f := range s.failureDetails {
		out.FailureDetails = append(out.FailureDetails, f)
	}
	for _, r := range s.records {
		if r.planReporter != nil {
			r.Plan = r.planReporter.CurrentPlan()
		}
		if r.originReporter != nil {
			v := r.originReporter.OriginAttempts()
			r.Origin = &v
			if dst, e := netip.ParseAddrPort(v.Selected); e == nil {
				r.Plan = RetargetOrigin(r.Plan, dst)
			}
		}
		if r.tlsWire != nil {
			v := r.tlsWire.Snapshot()
			r.TLS = &v
		}
		if r.Plan.Policy.Action == flowpolicy.DirectPlus && !r.DirectPlusApplied && s.cfg.TransformApplied != nil {
			source, _ := netip.ParseAddrPort(r.Source)
			r.DirectPlusApplied = s.cfg.TransformApplied(Request{Owner: r.Owner, Source: source, Host: r.Domain, Port: r.Port}, r.Plan)
			if r.DirectPlusApplied {
				s.records[r.ID] = r
			}
		}
		out.Records = append(out.Records, r)
	}
	return out
}
func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, e := s.l.Accept()
		if e != nil {
			s.cancel()
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			s.CloseConnections()
			return
		}
		acceptedAt := time.Now()
		select {
		case s.slots <- struct{}{}:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				<-s.slots
				c.Close()
				return
			}
			s.lastActivity = acceptedAt
			s.conns[c] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() {
					<-s.slots
					s.mu.Lock()
					delete(s.conns, c)
					s.lastActivity = time.Now()
					s.mu.Unlock()
					c.Close()
				}()
				s.handle(c, acceptedAt)
			}()
		default:
			s.reject("PROXY_CONNECTION_CAPACITY")
			c.Close()
		}
	}
}
func CanonicalHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, e := netip.ParseAddr(strings.Trim(host, "[]")); e == nil {
		return ip.Unmap().String(), nil
	}
	ascii, e := idna.Lookup.ToASCII(host)
	if e != nil || len(ascii) == 0 || len(ascii) > 253 {
		return "", errors.New("invalid origin hostname")
	}
	for _, v := range strings.Split(ascii, ".") {
		if len(v) == 0 || len(v) > 63 || v[0] == '-' || v[len(v)-1] == '-' {
			return "", errors.New("invalid hostname label")
		}
		for _, c := range v {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid hostname character")
			}
		}
	}
	return ascii, nil
}
func authority(value string, defaultPort uint16) (string, uint16, error) {
	h, p, e := net.SplitHostPort(value)
	if e != nil {
		h = value
		p = strconv.Itoa(int(defaultPort))
	}
	host, e := CanonicalHost(h)
	if e != nil {
		return "", 0, e
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("invalid origin port")
	}
	return host, uint16(port), nil
}
func readHeaders(b *bufio.Reader) ([]byte, error) {
	var h []byte
	for len(h) < 16384 {
		line, e := b.ReadSlice('\n')
		if e != nil {
			return nil, e
		}
		h = append(h, line...)
		if bytes.HasSuffix(h, []byte("\r\n\r\n")) {
			return h, nil
		}
	}
	return nil, errors.New("proxy header bound")
}
func (s *Server) reject(reason string) {
	s.mu.Lock()
	s.failures[reason]++
	s.mu.Unlock()
}
func (s *Server) handle(c net.Conn, acceptedAt time.Time) {
	lifetime, stopLifetime := context.WithCancel(s.ctx)
	defer stopLifetime()
	ctx, cancel := context.WithTimeout(lifetime, 8*time.Second)
	defer cancel()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	b := bufio.NewReaderSize(c, 8192)
	head, e := readHeaders(b)
	if e != nil {
		s.reject("PROXY_HEADER_READ_FAILED")
		return
	}
	parsed := bufio.NewReader(io.MultiReader(bytes.NewReader(head), b))
	request, e := http.ReadRequest(parsed)
	if e != nil {
		s.reject("PROXY_HEADER_PARSE_FAILED")
		return
	}
	secure := request.Method == "CONNECT"
	target := request.Host
	defaultPort := uint16(80)
	if secure {
		target = request.RequestURI
		defaultPort = 443
	} else if (request.URL.Scheme != "http" && !(request.URL.Scheme == "" && request.Method == "GET" && request.Host == "neexitlag-recovery-status.invalid" && request.URL.Path == "/status")) || request.URL.User != nil {
		writeError(c, 400)
		return
	}
	host, port, e := authority(target, defaultPort)
	if e != nil {
		writeError(c, 400)
		return
	}
	source, e := netip.ParseAddrPort(c.RemoteAddr().String())
	if e != nil || !source.Addr().IsLoopback() {
		writeError(c, 403)
		return
	}
	local, e := netip.ParseAddrPort(c.LocalAddr().String())
	if e != nil {
		return
	}
	if s.transportCheck(c, request, target) {
		return
	}
	if !secure && host == "neexitlag-recovery-status.invalid" && request.Method == "GET" && request.URL.Path == "/status" {
		expected := "Bearer " + s.cfg.MetadataToken
		if s.cfg.MetadataToken == "" || s.cfg.AuthorizeMetadata == nil || s.cfg.Metadata == nil || subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte(expected)) != 1 || s.cfg.AuthorizeMetadata(ctx, source, local) != nil {
			writeError(c, 403)
			return
		}
		snapshot := s.cfg.Metadata()
		raw, err := json.Marshal(snapshot)
		for err == nil && len(raw) > 58000 && (len(snapshot.Records) > 0 || len(snapshot.FailureDetails) > 0 || len(snapshot.PathMetrics) > 0 || len(snapshot.FirstByteMetrics) > 0) {
			snapshot.Truncated = true
			switch {
			case len(snapshot.Records) > 0:
				snapshot.Records = snapshot.Records[:len(snapshot.Records)-1]
			case len(snapshot.FailureDetails) > 0:
				snapshot.FailureDetails = snapshot.FailureDetails[:len(snapshot.FailureDetails)-1]
			case len(snapshot.FirstByteMetrics) > 0:
				snapshot.FirstByteMetrics = snapshot.FirstByteMetrics[:len(snapshot.FirstByteMetrics)-1]
				snapshot.FirstByteLost++
			case len(snapshot.PathMetrics) > 0:
				snapshot.PathMetrics = snapshot.PathMetrics[:len(snapshot.PathMetrics)-1]
			}
			raw, err = json.Marshal(snapshot)
		}
		if err != nil || len(raw) > 58000 {
			writeError(c, 503)
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(raw))
		c.Write(raw)
		return
	}
	var owner Owner
	forwarded := request.Header.Get("Neexitlag-Source") != "" || request.Header.Get("Neexitlag-Listener") != "" || request.Header.Get("Neexitlag-Plain") != ""
	originalSource := source
	plain := false
	if forwarded {
		original, se := netip.ParseAddrPort(request.Header.Get("Neexitlag-Source"))
		listener, le := netip.ParseAddrPort(request.Header.Get("Neexitlag-Listener"))
		if !secure || s.cfg.AuthorizeForwarded == nil || se != nil || le != nil || !original.Addr().IsLoopback() || !listener.Addr().IsLoopback() || original.Port() == 0 || listener.Port() == 0 {
			s.reject("FORWARDED_OWNER_REJECTED")
			writeError(c, 403)
			return
		}
		owner, e = s.cfg.AuthorizeForwarded(ctx, source, local, original, listener)
		originalSource = original
		plain = request.Header.Get("Neexitlag-Plain") == "1"
	} else {
		owner, e = s.cfg.Authorize(ctx, source, local)
	}
	request.Header.Del("Neexitlag-Source")
	request.Header.Del("Neexitlag-Listener")
	request.Header.Del("Neexitlag-Plain")
	if e != nil {
		reason := "PROXY_AUTHORIZATION_FAILED"
		for _, kind := range []error{ErrOwnerLookup, ErrOwnerToken, ErrOwnerSID, ErrOwnerProfile} {
			if errors.Is(e, kind) {
				reason = kind.Error()
				break
			}
		}
		s.reject(reason)
		writeError(c, 403)
		return
	}
	if !secure && host == "neexitlag-health.invalid" {
		s.health(c, owner, request.URL.Path)
		return
	}
	q := Request{Ingress: "PAC_CONNECT", Owner: owner, Source: originalSource, Host: host, Port: port, Secure: secure && !plain}
	if forwarded {
		q.Ingress = "PAC_RECOVERY"
	}
	started := time.Now()
	plan, planErr := s.cfg.Plan(ctx, q)
	// Planning may consume its budget; a valid route gets its own bounded OPEN.
	// Never detach from listener shutdown or reuse an expired planning context.
	cancel()
	if planErr != nil {
		// Keep bounded failure evidence, without recording arbitrary error strings,
		// URLs or credentials supplied by a transport implementation.
		plan.Probe = "ORIGIN_PLAN_FAILED"
		if errors.Is(planErr, ErrOriginDNS) {
			plan.Probe = "ORIGIN_DNS_FAILED"
		}
		if errors.Is(planErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			plan.Probe = "NETWORK_TIMEOUT"
		}
	}
	s.mu.Lock()
	s.next++
	id := s.next
	if len(s.records) >= 512 {
		old := uint64(0)
		for n, r := range s.records {
			if !r.Active && (old == 0 || n < old) {
				old = n
			}
		}
		if old != 0 {
			delete(s.records, old)
			s.lost++
		}
	}
	if len(s.records) >= 512 {
		s.mu.Unlock()
		writeError(c, 503)
		return
	}
	s.pathBeginLocked(owner.Profile)
	s.records[id] = Record{AcceptedAt: acceptedAt, FirstByteMS: -1, FirstByteMode: firstByteMode(plan), ID: id, Owner: owner, Domain: host, Port: port, Source: originalSource.String(), Plan: plan, PlanDurationMS: time.Since(started).Milliseconds(), EvidenceSource: q.Ingress, Started: started, Active: true, Result: "OPEN_PENDING"}
	s.mu.Unlock()
	finish := func(result string, tx, rx uint64) {
		s.mu.Lock()
		r := s.records[id]
		if r.FirstByteMS < 0 {
			if r.NoReplyReason == "" {
				switch {
				case errors.Is(planErr, ErrOriginDNS):
					r.NoReplyReason = "ORIGIN_DNS_FAILED"
				case result == "ORIGIN_PLAN_FAILED" && (isTimeout(planErr) || r.Plan.Probe == "NETWORK_TIMEOUT"):
					r.NoReplyReason = "TIMEOUT"
				case result == "ORIGIN_PLAN_FAILED":
					r.NoReplyReason = "POLICY_OR_PLAN_FAILED"
				default:
					r.NoReplyReason = "UNCLASSIFIED"
				}
			}
			s.firstBytes.observe(r, -1)
		}
		r.Active = false
		r.Result = result
		p := s.paths[r.Owner.Profile]
		if result == "ORIGIN_PLAN_FAILED" || result == "UPSTREAM_OPEN_FAILED" {
			p.Failed++
			phase := "OPEN"
			reason := r.OpenFailure
			if result == "ORIGIN_PLAN_FAILED" {
				phase = "PLAN"
				reason = r.Plan.Probe
			}
			s.pathFailureLocked(r, phase, reason)
		} else if p.Active > 0 {
			p.Active--
		}
		if p.Profile != "" {
			s.paths[r.Owner.Profile] = p
		}
		r.Sent = tx
		r.Received = rx
		s.records[id] = r
		s.mu.Unlock()
	}
	if planErr != nil || plan.Policy.Action == flowpolicy.Block {
		s.reject(plan.Probe)
		finish("ORIGIN_PLAN_FAILED", 0, 0)
		writeError(c, 502)
		return
	}
	openCtx, stopOpen := context.WithTimeout(lifetime, 3*time.Second)
	defer stopOpen()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	openStarted := time.Now()
	var upstream net.Conn
	if s.cfg.OpenPlan != nil {
		upstream, plan, e = s.cfg.OpenPlan(openCtx, q, plan)
		s.mu.Lock()
		r := s.records[id]
		r.Plan = plan
		s.records[id] = r
		s.mu.Unlock()
	} else {
		upstream, e = s.cfg.Open(openCtx, q, plan)
	}
	s.mu.Lock()
	openedRecord := s.records[id]
	openedRecord.OpenDurationMS = time.Since(openStarted).Milliseconds()
	openedRecord.FirstByteMode = firstByteMode(plan)
	s.records[id] = openedRecord
	s.mu.Unlock()
	if e != nil {
		s.mu.Lock()
		r := s.records[id]
		r.OpenFailure = openFailure(e)
		r.NoReplyReason = noReplyFailure(e)
		s.records[id] = r
		s.mu.Unlock()
		s.reject(openFailure(e))
		finish("UPSTREAM_OPEN_FAILED", 0, 0)
		writeError(c, 502)
		return
	}
	s.mu.Lock()
	s.pathOpenedLocked(owner.Profile)
	s.mu.Unlock()
	if secure && port == 443 && plan.Enabled && plan.Policy.Action == flowpolicy.Direct && !plan.FirstFlightManaged && s.cfg.OnStall != nil {
		upstream = s.watchDirect(lifetime, upstream, q, plan, id, 0)
	}

	s.mu.Lock()
	s.conns[upstream] = true
	s.mu.Unlock()
	defer func() { upstream.Close(); s.mu.Lock(); delete(s.conns, upstream); s.mu.Unlock() }()
	// Once established, this exact upstream is immutable. No route fallback or
	// replay is permitted after any client bytes have been sent.
	c.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	closeEvidence := &tunnelCloseEvidence{ctx: s.ctx}
	if reporter, ok := upstream.(PlanReporter); ok {
		s.mu.Lock()
		r := s.records[id]
		r.planReporter = reporter
		s.records[id] = r
		s.mu.Unlock()
	}
	if reporter, ok := upstream.(OriginReporter); ok {
		s.mu.Lock()
		r := s.records[id]
		r.originReporter = reporter
		s.records[id] = r
		s.mu.Unlock()
	}
	if secure {
		closeEvidence.tlsWire = &TLSWireObserver{}
		s.mu.Lock()
		r := s.records[id]
		r.tlsWire = closeEvidence.tlsWire
		s.records[id] = r
		s.mu.Unlock()
	}
	setCloseCause := func() {
		s.mu.Lock()
		r := s.records[id]
		r.NoReplyReason = closeEvidence.cause()
		r.RequestPayloadSeen = closeEvidence.clientData.Load()
		r.OriginPayloadSeen = closeEvidence.originData.Load()
		s.records[id] = r
		s.mu.Unlock()
	}
	if !secure {
		request.RequestURI = ""
		request.Close = true
		request.Header.Del("Proxy-Authorization")
		request.Header.Del("Proxy-Connection")
		var sent uint64
		closeEvidence.clientData.Store(true)
		if e = request.Write(countWriter{Writer: closeWriter{Writer: upstream, evidence: closeEvidence}, add: func(n int) { sent += uint64(n); s.account(id, uint64(n), 0) }}); e != nil {
			setCloseCause()
			finish("HTTP_WRITE_FAILED", sent, 0)
			return
		}
		n, e := io.Copy(countWriter{Writer: closeWriter{Writer: c, evidence: closeEvidence, client: true}, add: func(n int) { s.account(id, 0, uint64(n)) }}, closeReader{Reader: upstream, evidence: closeEvidence})
		result := "HTTP_RESPONSE"
		if e != nil {
			result = "HTTP_READ_FAILED"
		}
		setCloseCause()
		finish(result, sent, uint64(n))
		return
	}
	if _, e = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		closeEvidence.terminal("client-write", e)
		setCloseCause()
		finish("CLIENT_CLOSED", 0, 0)
		return
	}
	s.mu.Lock()
	r := s.records[id]
	r.Result = "TCP_ESTABLISHED_HTTP_RESULT_UNKNOWN"
	s.records[id] = r
	s.mu.Unlock()
	type copied struct {
		n   int64
		err error
	}
	out := make(chan copied, 1)
	go func() {
		n, e := io.Copy(countWriter{Writer: closeWriter{Writer: upstream, evidence: closeEvidence}, add: func(n int) { s.account(id, uint64(n), 0) }}, closeReader{Reader: parsed, evidence: closeEvidence, client: true})
		if v, ok := upstream.(interface{ CloseWrite() error }); ok {
			v.CloseWrite()
		}
		out <- copied{n, e}
	}()
	rx, re := io.Copy(countWriter{Writer: closeWriter{Writer: c, evidence: closeEvidence, client: true}, add: func(n int) { s.account(id, 0, uint64(n)) }}, closeReader{Reader: upstream, evidence: closeEvidence})
	closeEvidence.forcing.Store(true)
	c.Close()
	upstream.Close()
	tx := <-out
	result := "TUNNEL_CLOSED"
	if re != nil || tx.err != nil {
		result = "TUNNEL_ENDED"
	}
	if errors.Is(re, ErrDirectMidstreamStall) {
		result = "DIRECT_MIDSTREAM_STALL"
		s.reject(result)
	}
	setCloseCause()
	finish(result, uint64(tx.n), uint64(rx))
}
func writeError(c net.Conn, code int) {
	c.SetWriteDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code))
}

// Account only bytes actually written to the corresponding socket. Active
// tunnels expose live counters; a completed copy replaces them with its totals.
func (s *Server) account(id, tx, rx uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.records[id]
	if rx > 0 && r.FirstByteMS < 0 {
		elapsed := time.Since(r.AcceptedAt)
		r.FirstByteMS = float64(elapsed) / float64(time.Millisecond)
		s.firstBytes.observe(r, elapsed)
	}
	r.Sent += tx
	r.Received += rx
	s.pathBytesLocked(r, tx, rx)
	s.records[id] = r
}

type countWriter struct {
	io.Writer
	add func(int)
}

func (w countWriter) Write(p []byte) (int, error) {
	n, e := w.Writer.Write(p)
	if n > 0 {
		w.add(n)
	}
	return n, e
}

// Return only stable error classes/OS codes, never remote messages or secrets.
func openFailure(err error) string {
	if errors.Is(err, ErrOriginCandidatePolicy) {
		return "ORIGIN_CANDIDATE_POLICY_BLOCK"
	}
	var typed interface{ FailureReason() string }
	if errors.As(err, &typed) {
		switch reason := typed.FailureReason(); reason {
		case "OPAQUE_GOOGLE_RELAY_ADMISSION_CAPACITY", "LOCAL_FLOW_RESERVATION_IN_USE", "NATIVE_PAC_DELEGATION_INVALID", "NATIVE_PAC_DELEGATION_UNAVAILABLE", "NATIVE_CAPTURE_NOT_READY", "NATIVE_PROFILE_CHANGED", "NATIVE_OWNER_SID_MISMATCH", "NATIVE_EVIDENCE_CAPACITY", "relay_destination_denied", "relay_flow_capacity", "upstream_dial_timeout", "upstream_connection_refused", "upstream_dial_failed", "authorization_expired_or_revoked", "authorization_lease_expired", "device_revoked", "relay_rejected_unspecified", "stream_capacity", "caller_cancelled", "open_ack_timeout", "open_stream_reset", "open_ack_eof", "open_io_failed", "transport_open_failed", "session_creation_failed":
			return strings.ToUpper(reason)
		}
	}
	var timed net.Error
	if errors.As(err, &timed) && timed.Timeout() {
		return "UPSTREAM_OPEN_TIMEOUT"
	}

	if errors.Is(err, ErrVideoRelayAdmission) {
		return "GOOGLEVIDEO_RELAY_ADMISSION_CAPACITY"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "UPSTREAM_OPEN_TIMEOUT"
	}
	if errors.Is(err, context.Canceled) {
		return "UPSTREAM_OPEN_CANCELED"
	}
	var op *os.SyscallError
	if errors.As(err, &op) {
		var code syscall.Errno
		if errors.As(err, &code) {
			switch op.Syscall {
			case "bind", "connectex", "getsockname", "WSASocket", "bound_bind", "bound_getsockname", "bound_connectex", "bound_connect_result", "bound_connect_context", "connect_event":
				return strings.ToUpper(op.Syscall) + "_" + strconv.FormatUint(uint64(code), 10)
			}
		}
	}
	return "UPSTREAM_OPEN_FAILED"
}

// A readiness nonce is consumed only by a successfully authorized Chrome TCP
// owner. IPC reachability or a GUI socket cannot certify Chrome PAC operation.
// ErrVideoRelayAdmission is bounded local admission, not a VPS health failure.
var ErrVideoRelayAdmission = errors.New("GOOGLEVIDEO_RELAY_ADMISSION_CAPACITY")

type healthChallenge struct {
	profile string
	expires time.Time
}

func (s *Server) Challenge(profile string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(nonce[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.verified, profile)
	for k, v := range s.challenges {
		if !time.Now().Before(v.expires) || v.profile == profile {
			delete(s.challenges, k)
		}
	}
	if len(s.challenges) >= 16 {
		return "", errors.New("Chrome activation capacity")
	}
	s.challenges[token] = healthChallenge{profile, time.Now().Add(45 * time.Second)}
	return "http://neexitlag-health.invalid/ready/" + token, nil
}
func (s *Server) health(c net.Conn, owner Owner, path string) {
	token := strings.TrimPrefix(path, "/ready/")
	s.mu.Lock()
	challenge, ok := s.challenges[token]
	valid := ok && challenge.profile == owner.Profile && time.Now().Before(challenge.expires) && (s.confirmed[owner.Profile] || len(s.confirmed) < 128)
	if valid {
		delete(s.challenges, token)
		s.verified[owner.Profile] = token
	}
	s.mu.Unlock()
	if !valid {
		s.reject("CHROME_READINESS_REJECTED")
		writeError(c, 403)
		return
	}
	io.WriteString(c, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 29\r\n\r\nNeExitLag Chrome transport OK")
}
func (s *Server) Confirmed(profile string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.ctx.Err() == nil && s.confirmed[profile]
}
func (s *Server) RestoreConfirmed(profiles []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range profiles {
		if len(s.confirmed) < 128 {
			s.confirmed[p] = true
		}
	}
}

// ReadinessState is diagnostic only; it never exports the nonce or grants
// authorization. Confirmation still requires an owner-authenticated health GET.
func (s *Server) ReadinessState(profile, url string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return "LISTENER_UNAVAILABLE"
	}
	token := strings.TrimPrefix(url, "http://neexitlag-health.invalid/ready/")
	if token != "" && s.verified[profile] == token {
		return "OWNER_NONCE_VERIFIED"
	}
	challenge, ok := s.challenges[token]
	if !ok || challenge.profile != profile {
		return "NONCE_INVALIDATED"
	}
	if !time.Now().Before(challenge.expires) {
		return "NONCE_EXPIRED"
	}
	return "WAITING_FOR_BROWSER_REQUEST"
}

func (s *Server) HealthVerified(profile, url string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := strings.TrimPrefix(url, "http://neexitlag-health.invalid/ready/")
	return !s.closed && s.ctx.Err() == nil && token != "" && s.verified[profile] == token
}

func (s *Server) Forget(profile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.confirmed, profile)
	delete(s.verified, profile)
	for token, challenge := range s.challenges {
		if challenge.profile == profile {
			delete(s.challenges, token)
		}
	}
}

func (s *Server) AuthorizeProfile(profile, url string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := strings.TrimPrefix(url, "http://neexitlag-health.invalid/ready/")
	if s.closed || s.ctx.Err() != nil || token == "" || s.verified[profile] != token {
		return false
	}
	if !s.confirmed[profile] && len(s.confirmed) >= 128 {
		return false
	}
	s.confirmed[profile] = true
	return true
}
