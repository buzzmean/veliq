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
	At        time.Time `json:"at"`
	Profile   string    `json:"profile_id"`
	Host      string    `json:"domain"`
	Type      uint16    `json:"query_type"`
	Path      string    `json:"path"`
	Result    string    `json:"result"`
	Addresses int       `json:"addresses"`
}

func newBrowserDNSRuntime() *browserDNSRuntime {
	return &browserDNSRuntime{slots: make(chan struct{}, 16), streams: make(chan struct{}, 16)}
}
func (s *browserDNSRuntime) record(p, host string, typ uint16, path, result string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	if path == "AUTHENTICATED_RELAY_DOH" {
		s.relay++
	} else {
		s.system++
	}
	if result != "DNS_RESPONSE" {
		s.failed++
	}
	if len(s.records) >= 64 {
		s.records = s.records[1:]
	}
	s.records = append(s.records, browserDNSRecord{time.Now(), p, host, typ, path, result, n})
}
func (s *browserDNSRuntime) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{"scope": "ATTRIBUTED_NATIVE_BROWSER_IPV4_UDP_TCP_53; Windows DNS service queries remain system-owned", "secure_dns_policy": "KNOWN_DOH_AUTHENTICATED_RELAY; no forced automatic fallback", "encrypted_answers": "NOT_OBSERVED; no TLS interception", "queries": s.queries, "relay_doh": s.relay, "system_dns": s.system, "failed": s.failed, "active": len(s.slots), "max_active": cap(s.slots), "records": append([]browserDNSRecord{}, s.records...)}
}

func (c *Controller) browserDNSDecision(p profiles.Profile, id wp.ProcessIdentity, t wp.Tuple, d wp.Decision, network string) wp.Decision {
	d.Deferred = false
	d.ResolveDomain = nil
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
		return c.exchangeBrowserDNS(ctx, cur, t, query, c.browserDNSRelayWire)
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
	if cur.enabled && c.browserDPILocalOrigin(host) {
		path = "DPI_LOCAL_SYSTEM_DNS"
		answer, err = browserproxy.ExchangeSystemDNS(ctx, t.Protocol+"4", t.Destination.String(), query)
	} else if cur.enabled && c.browserOriginPolicy(host).Kind != "" {
		path = "AUTHENTICATED_RELAY_DOH"
		if cur.network == "" {
			return nil, errors.New("BROWSER_DNS_NETWORK_UNAVAILABLE")
		}
		answer, err = relay(ctx, cur, t, query)
	} else {
		answer, err = browserproxy.ExchangeSystemDNS(ctx, t.Protocol+"4", t.Destination.String(), query)
	}
	var hints []browserproxy.DNSHint
	if err == nil {
		if t.Protocol == "udp" {
			answer = browserproxy.DNSDatagramResponse(query, answer)
		}
		hints, err = browserproxy.ValidateDNSResponse(query, answer)
	}
	result := "DNS_RESPONSE"
	if err != nil {
		result = "BROWSER_DNS_TRANSACTION_FAILED"
	}
	state.record(cur.profile.ID, host, uint16(q.Type), path, result, len(hints))
	if err != nil {
		return nil, errors.New(result)
	} // Never leak resolver errors/payload.
	if cur.enabled {
		c.browser.domains.observeBrowserDNS(cur.network, cur.profile.ID, hints, time.Now())
	}
	return answer, nil
}

func (c *Controller) browserDNSRelayWire(ctx context.Context, cur profilesResult, t wp.Tuple, query []byte) ([]byte, error) {
	relay := cur.profile.RelayID
	if relay == "" {
		relay = "VPS-01"
	}
	owner := browserproxy.Owner{PID: cur.id.PID, Birth: cur.id.CreationTime, Exe: cur.id.Path, Profile: cur.profile.ID}
	return browserproxy.NewDoHResolver().ExchangeWire(ctx, query, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
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
