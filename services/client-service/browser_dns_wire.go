package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/netdiagnostic"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

type browserDNSRuntime struct {
	streams chan struct{}

	mu                             sync.Mutex
	slots                          chan struct{}
	queries, relay, system, failed uint64
	records                        []browserDNSRecord
}
type browserDNSRecord struct {
	Network   string                  `json:"network"`
	ID        uint64                  `json:"id"`
	Diagnosis netdiagnostic.Diagnosis `json:"diagnosis"`
	At        time.Time               `json:"at"`
	Profile   string                  `json:"profile_id"`
	Host      string                  `json:"domain"`
	Type      uint16                  `json:"query_type"`
	Path      string                  `json:"path"`
	Result    string                  `json:"result"`
	Addresses int                     `json:"addresses"`
}

func newBrowserDNSRuntime() *browserDNSRuntime {
	return &browserDNSRuntime{slots: make(chan struct{}, 16), streams: make(chan struct{}, 16)}
}
func (s *browserDNSRuntime) record(network, p, host string, typ uint16, path, result string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	if path == "AUTHENTICATED_RELAY_DOH" {
		s.relay++
	} else {
		s.system++
	}
	if result != "DNS_RESPONSE" && result != "DNS_RESPONSE_NO_ADDRESS_HINTS" && result != "DNS_NODATA" && result != "DNS_TRUNCATED" && result != "DNS_CANCELED" {
		s.failed++
	}
	if len(s.records) >= 64 {
		s.records = s.records[1:]
	}
	s.records = append(s.records, browserDNSRecord{Network: network, ID: s.queries, Diagnosis: netdiagnostic.DiagnoseDNS(result), At: time.Now(), Profile: p, Host: host, Type: typ, Path: path, Result: result, Addresses: n})
}
func (s *browserDNSRuntime) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{"scope": "ATTRIBUTED_NATIVE_BROWSER_IPV4_UDP_TCP_53; Windows DNS service queries remain system-owned", "secure_dns_policy": "KNOWN_DOH_AUTHENTICATED_RELAY; no forced automatic fallback", "encrypted_answers": "NOT_OBSERVED; no TLS interception", "queries": s.queries, "relay_doh": s.relay, "system_dns": s.system, "failed": s.failed, "active": len(s.slots), "max_active": cap(s.slots), "records_omitted": s.queries - uint64(len(s.records)), "records": append([]browserDNSRecord{}, s.records...)}
}

func (c *Controller) browserDNSDecision(p profiles.Profile, id wp.ProcessIdentity, t wp.Tuple, d wp.Decision, network string) wp.Decision {
	d.Deferred = false
	d.ResolveDomain = nil
	revision := c.policyRevision(p)
	d.DNSExchange = func(ctx context.Context, query []byte) ([]byte, error) {
		if !wp.IsCurrent(id) {
			return nil, errors.New("BROWSER_DNS_OWNER_EXITED")
		}
		if c.BrowserOwnerSID != "" {
			sid, err := wp.ProcessUserSID(id)
			if err != nil || sid != c.BrowserOwnerSID {
				return nil, errors.New("BROWSER_DNS_OWNER_SID_MISMATCH")
			}
		}
		cur, err := c.browserProfile(browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID})
		if err != nil {
			return nil, errors.New("BROWSER_DNS_PROFILE_CHANGED")
		}
		if cur.network != network {
			return nil, errors.New("BROWSER_DNS_NETWORK_CHANGED")
		}
		if !cur.enabled || cur.routingDisabled || c.policyRevision(cur.profile) != revision {
			return nil, errors.New("BROWSER_DNS_PROFILE_CHANGED")
		}
		return c.exchangeBrowserDNSChecked(ctx, cur, t, query, c.browserDNSRelayWire, c.browserDNSScopeCheck(cur))
	}
	if t.Protocol == "tcp" {
		d.NewConnectionsOnly = true
		d.OpenDeferred = func(_ context.Context, decision wp.Decision, _ string) (net.Conn, wp.Decision, error) {
			if c.ctx == nil {
				return nil, decision, errors.New("BROWSER_DNS_SERVICE_NOT_RUNNING")
			}
			select {
			case c.browser.dnsWire.streams <- struct{}{}:
			default:
				return nil, decision, errors.New("BROWSER_DNS_STREAM_CAPACITY")
			}
			return &browserDNSStream{Conn: browserproxy.NewDNSStream(c.ctx, decision.DNSExchange), release: func() { <-c.browser.dnsWire.streams }}, decision, nil
		}
	}
	return d
}

// Pure transaction boundary is fixture-testable. Runtime calls above revalidate
// PID/birth/path/SID/profile and network before accepting each DNS message.
func (c *Controller) exchangeBrowserDNS(ctx context.Context, cur profilesResult, t wp.Tuple, query []byte, relay func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error)) ([]byte, error) {
	return c.exchangeBrowserDNSChecked(ctx, cur, t, query, relay, nil)
}

// Проверка scope до I/O и перед доставкой: устаревший ответ не становится DNS hint.
func (c *Controller) exchangeBrowserDNSChecked(ctx context.Context, cur profilesResult, t wp.Tuple, query []byte, relay func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error), check func() error) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return nil, errors.New("BROWSER_DNS_TRANSACTION_FAILED")
	}
	if check != nil {
		if err := check(); err != nil {
			return nil, err
		}
	}
	q, err := browserproxy.DNSQuestion(query)
	if err != nil {
		return nil, err
	}
	host := browserproxy.DNSHost(q)
	state := c.browser.dnsWire
	select {
	case state.slots <- struct{}{}:
		defer func() { <-state.slots }()
	default:
		return nil, errors.New("BROWSER_DNS_CAPACITY")
	}
	path := "SYSTEM_DNS"
	var answer []byte
	if cur.enabled && c.browserOriginPolicy(host).Kind != "" {
		path = "AUTHENTICATED_RELAY_DOH"
		if cur.network == "" {
			return nil, errors.New("BROWSER_DNS_NETWORK_UNAVAILABLE")
		}
		answer, err = relay(ctx, cur, t, query)
	} else {
		answer, err = browserproxy.ExchangeSystemDNS(ctx, t.Protocol+"4", t.Destination.String(), query)
	}
	scopeChanged := check != nil && check() != nil
	if scopeChanged {
		err = errors.New("BROWSER_DNS_SCOPE_CHANGED")
	} else if ctx.Err() != nil {
		err = ctx.Err()
	}
	var hints []browserproxy.DNSHint
	invalidReply := false
	if err == nil {
		if t.Protocol == "udp" {
			answer = browserproxy.DNSDatagramResponse(query, answer)
		}
		hints, err = browserproxy.ValidateDNSResponse(query, answer)
		invalidReply = err != nil
	}
	result := "DNS_RESPONSE"
	if err != nil {
		result = "BROWSER_DNS_TRANSACTION_FAILED"
		var timeout net.Error
		if scopeChanged {
			result = "DNS_SCOPE_CHANGED"
		} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
			result = "DNS_TIMEOUT"
		} else if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			result = "DNS_CANCELED"
		} else if invalidReply {
			result = "DNS_INVALID_RESPONSE"
		}
	} else {
		result = browserproxy.DNSResponseStatus(query, answer)
	}
	state.record(cur.network, cur.profile.ID, host, uint16(q.Type), path, result, len(hints))
	if err != nil {
		return nil, errors.New("BROWSER_DNS_TRANSACTION_FAILED")
	} // Never leak resolver errors/payload.
	if cur.enabled {
		c.browser.domains.observeBrowserDNS(cur.network, cur.profile.ID, hints, time.Now())
	}
	return answer, nil
}

// OS identity проверяется заново, а revision фиксируется до начала ожидания.
func (c *Controller) browserDNSScopeCheck(before profilesResult) func() error {
	revision := c.policyRevision(before.profile)
	return func() error {
		if !wp.IsCurrent(before.id) {
			return errors.New("BROWSER_DNS_OWNER_EXITED")
		}
		if c.BrowserOwnerSID != "" {
			sid, err := wp.ProcessUserSID(before.id)
			if err != nil || sid != c.BrowserOwnerSID {
				return errors.New("BROWSER_DNS_OWNER_SID_MISMATCH")
			}
		}
		after, err := c.browserProfile(browserproxy.Owner{PID: before.id.PID, Birth: before.id.CreationTime, Exe: before.id.Path, Profile: before.profile.ID})
		if err != nil || !browserDNSSameScope(before, after, revision, c.policyRevision(after.profile)) {
			return errors.New("BROWSER_DNS_SCOPE_CHANGED")
		}
		return nil
	}
}

func browserDNSSameScope(before, after profilesResult, revision, currentRevision string) bool {
	return before.network == after.network && before.enabled == after.enabled && before.routingDisabled == after.routingDisabled && before.id == after.id && before.profile.ID == after.profile.ID && revision == currentRevision
}

func (c *Controller) browserDNSRelayWire(ctx context.Context, cur profilesResult, t wp.Tuple, query []byte) ([]byte, error) {
	question, err := browserproxy.DNSQuestion(query)
	if err != nil || !cur.enabled || c.browserOriginPolicy(browserproxy.DNSHost(question)).Kind == "" {
		return nil, errors.New("BROWSER_DNS_RECOVERY_NOT_AUTHORIZED")
	}
	check := c.browserDNSScopeCheck(cur)
	relay := cur.profile.RelayID
	if relay == "" {
		relay = "VPS-01"
	}
	owner := browserproxy.Owner{PID: cur.id.PID, Birth: cur.id.CreationTime, Exe: cur.id.Path, Profile: cur.profile.ID}
	return browserproxy.NewDoHResolver().ExchangeWire(ctx, query, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		// Не дать cached-PAC DIRECT compatibility обойти fail-closed при OFF между попытками.
		if err := check(); err != nil {
			return nil, err
		}
		// A unique tuple per resolver query avoids Engine FlowExists collisions
		// for parallel A/AAAA/HTTPS queries on one browser UDP source socket.
		reserved, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		q := browserproxy.Request{Owner: owner, Source: reserved.Addr().(*net.TCPAddr).AddrPort(), Port: 443, Secure: true}
		p := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: dst, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Source: "browser_dns_wire_doh"}}
		conn, err := c.browserOpenUnobserved(ctx, q, p)
		reserved.Close()
		return conn, err
	})
}

type browserDNSStream struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *browserDNSStream) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
