package browserproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Recovery is a second, bounded local transport, supervised by the owner GUI.
// It has no device credentials and cannot originate authenticated relay flows.
// New connections first use the service's authenticated origin planner. Only a
// failed local connect BEFORE any application data permits ordinary DIRECT.
// Any primary HTTP rejection is final; established bytes are never replayed.
type RecoverySettings struct {
	CheckTarget string `json:"check_target,omitempty"`
	CheckToken  string `json:"check_token,omitempty"`

	GuardFile  string   `json:"guard_file"`
	Primary    string   `json:"primary"`
	Executable string   `json:"executable"`
	Profile    string   `json:"profile_id"`
	Domains    []string `json:"protected_domains"`
	Strict     bool     `json:"strict"`
}
type Recovery struct {
	token         string
	metadataOwner func(context.Context, netip.AddrPort, netip.AddrPort) error
	server        *Server
	mu            sync.RWMutex
	settings      *RecoverySettings
	direct        func(context.Context, Request) (net.Conn, error)
}

func ListenRecovery(ctx context.Context, address string, authorize func(context.Context, netip.AddrPort, netip.AddrPort, RecoverySettings) (Owner, error), direct func(context.Context, Request) (net.Conn, error)) (*Recovery, error) {
	if authorize == nil {
		return nil, errors.New("recovery owner authorization required")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	r := &Recovery{direct: direct, token: hex.EncodeToString(nonce)}
	s, err := Listen(ctx, Config{Address: address, TransportCheck: func() (string, string) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		if r.settings == nil {
			return "", ""
		}
		return r.settings.CheckTarget, r.settings.CheckToken
	}, MetadataToken: r.token, AuthorizeMetadata: func(ctx context.Context, source, local netip.AddrPort) error {
		r.mu.RLock()
		auth := r.metadataOwner
		r.mu.RUnlock()
		if auth == nil {
			return ErrOwnerSID
		}
		return auth(ctx, source, local)
	}, Metadata: r.DirectSnapshot, Authorize: func(ctx context.Context, source, local netip.AddrPort) (Owner, error) {
		r.mu.RLock()
		current := r.settings
		r.mu.RUnlock()
		if current == nil {
			return Owner{}, ErrOwnerProfile
		}
		return authorize(ctx, source, local, *current)
	}, Plan: func(ctx context.Context, q Request) (Plan, error) {
		r.mu.RLock()
		current := r.settings
		r.mu.RUnlock()
		if current == nil || (!recoveryCompatibilityAuthorized(*current) && guardedRecoveryDomain(q.Host, *current)) {
			return Plan{}, errors.New("RECOVERY_PROTECTED_ORIGIN_REJECTED")
		}
		return Plan{Policy: flowpolicy.Result{Action: flowpolicy.Direct, Reason: "recovery forwarding; primary route recorded by service"}, Probe: "PRIMARY_FORWARD_OR_ORDINARY_DIRECT"}, nil
	}, OpenPlan: func(ctx context.Context, q Request, p Plan) (net.Conn, Plan, error) { return r.open(ctx, q, p) }})
	if err != nil {
		return nil, err
	}
	r.server = s
	return r, nil
}
func (r *Recovery) Address() string { return r.server.Address() }
func (r *Recovery) Close()          { r.server.Close() }
func (r *Recovery) Configure(cfg RecoverySettings) error {
	primary, err := netip.ParseAddrPort(cfg.Primary)
	if err != nil || !primary.Addr().Is4() || !primary.Addr().IsLoopback() || primary.Port() == 0 || cfg.Primary == r.Address() || cfg.Profile == "" || len(cfg.Profile) > 128 || len(cfg.Executable) > 2048 || !strings.HasSuffix(strings.ToLower(cfg.Executable), ".exe") || len(cfg.Domains) > 512 {
		return errors.New("invalid recovery configuration")
	}
	guards := []string{"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "chat.com", "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com", "ggpht.com"}
	for _, host := range cfg.Domains {
		canonical, err := CanonicalHost(host)
		if err != nil {
			return err
		}
		guards = append(guards, canonical)
	}
	cfg.Domains = guards
	r.mu.Lock()
	r.settings = &cfg
	r.mu.Unlock()
	return nil
}
func guardedRecoveryDomain(host string, cfg RecoverySettings) bool {
	if cfg.Strict {
		return true
	}
	for _, d := range cfg.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
func (r *Recovery) open(ctx context.Context, q Request, p Plan) (net.Conn, Plan, error) {
	r.mu.RLock()
	current := r.settings
	r.mu.RUnlock()
	if current == nil || (!recoveryCompatibilityAuthorized(*current) && guardedRecoveryDomain(q.Host, *current)) {
		return nil, p, errors.New("RECOVERY_PROTECTED_ORIGIN_REJECTED")
	}
	if recoveryCompatibilityAuthorized(*current) {
		return r.openDirect(ctx, q, p, "BROWSER_DISABLED_DIRECT")
	}
	// Only a loopback connect is attempted before considering ordinary DIRECT.
	up, err := (&net.Dialer{}).DialContext(ctx, "tcp4", current.Primary)
	if err == nil {
		up.SetDeadline(deadline(ctx))
		plain := "0"
		if !q.Secure {
			plain = "1"
		}
		_, err = fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nNeexitlag-Source: %s\r\nNeexitlag-Listener: %s\r\nNeexitlag-Plain: %s\r\n\r\n", net.JoinHostPort(q.Host, strconv.Itoa(int(q.Port))), net.JoinHostPort(q.Host, strconv.Itoa(int(q.Port))), q.Source, r.Address(), plain)
		if err != nil {
			up.Close()
			return nil, p, err
		}
		b := bufio.NewReaderSize(up, 8192)
		head, e := readHeaders(b)
		if e != nil {
			up.Close()
			return nil, p, errors.New("RECOVERY_PRIMARY_HEADER_FAILED")
		}
		response, e := http.ReadResponse(bufio.NewReader(strings.NewReader(string(head))), nil)
		if e != nil || response.StatusCode != 200 {
			up.Close()
			return nil, p, errors.New("RECOVERY_PRIMARY_REJECTED")
		}
		up.SetDeadline(time.Time{})
		p.Probe = "RECOVERY_FORWARDED_RESULT_IN_SERVICE"
		return &bufferedRecoveryConn{Conn: up, reader: b}, p, nil
	}
	if ctx.Err() != nil {
		return nil, p, ctx.Err()
	}
	if !recoveryDirectAuthorized(*current, q.Host) {
		return nil, p, errors.New("RECOVERY_DIRECT_NOT_AUTHORIZED")
	}
	return r.openDirect(ctx, q, p, "RECOVERY_DIRECT_SOCKET")
}
func (r *Recovery) openDirect(ctx context.Context, q Request, p Plan, probe string) (net.Conn, Plan, error) {
	var err error
	var direct net.Conn
	if r.direct != nil {
		direct, err = r.direct(ctx, q)
	} else {
		direct, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(q.Host, strconv.Itoa(int(q.Port))))
	}
	if err != nil {
		return nil, p, err
	}
	p.Probe = probe
	p.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Source: "browser_recovery_direct", Reason: "primary service unavailable; ordinary DIRECT socket established"}
	p.Destination, _ = netip.ParseAddrPort(direct.RemoteAddr().String())
	return direct, p, nil
}
func deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(8 * time.Second)
}

type bufferedRecoveryConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedRecoveryConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedRecoveryConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

func (r *Recovery) MetadataToken() string { return r.token }
func (r *Recovery) AuthorizeMetadata(auth func(context.Context, netip.AddrPort, netip.AddrPort) error) {
	r.mu.Lock()
	r.metadataOwner = auth
	r.mu.Unlock()
}
func (r *Recovery) DirectSnapshot() Snapshot {
	snapshot := r.server.Snapshot()
	snapshot.ProcessRole = "OWNER_RECOVERY"
	records := []Record{}
	for _, record := range snapshot.Records {
		if record.Plan.Probe == "RECOVERY_DIRECT_SOCKET" || record.Plan.Probe == "BROWSER_DISABLED_DIRECT" {
			record.EvidenceSource = "RECOVERY_DIRECT"
			records = append(records, record)
		}
	}
	snapshot.Records = records
	return snapshot
}
