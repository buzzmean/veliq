package clientservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/measurement"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/internal/clientconfig"
	"github.com/buzzmean/neexitlag/internal/e2eprobe"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Manifest = clientconfig.Manifest

func LoadManifest(path string) (Manifest, error) { return clientconfig.Load(path) }
func (c *Controller) ConnectRemote(ctx context.Context, m Manifest) error {
	m = clientconfig.Normalize(m)
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	raw, e := os.ReadFile(m.TrustFile)
	if e != nil {
		return e
	}
	var encoded map[string]string
	if e = json.Unmarshal(raw, &encoded); e != nil {
		return e
	}
	keys := map[string]ed25519.PublicKey{}
	for id, value := range encoded {
		key, e := security.DecodePublicKey(value)
		if e != nil {
			return e
		}
		keys[id] = key
	}
	identity, key, e := security.LoadOrCreateIdentity(m.DeviceIdentityFile)
	if e != nil {
		return e
	}
	certRaw, e := os.ReadFile(m.DeviceCertificate)
	if e != nil {
		return e
	}
	certPool := x509.NewCertPool()
	caRaw, e := os.ReadFile(m.CAFile)
	if e != nil {
		return e
	}
	if !certPool.AppendCertsFromPEM(caRaw) {
		return errors.New("invalid relay CA")
	}
	block, _ := pem.Decode(certRaw)
	if block == nil {
		return errors.New("invalid device certificate")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return errors.New("invalid device certificate")
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !public.Equal(key.Public()) {
		return errors.New("device certificate does not match persisted identity")
	}
	renewer := &certRenewer{path: m.DeviceCertificate, roots: certPool, key: key}
	renewer.current.Store(&tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf})
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: certPool, GetClientCertificate: renewer.clientCertificate}
	cache := security.NewConfigCache(keys, filepath.Join(m.StateDirectory, "signed-config.json"))
	_ = cache.Load(time.Now())
	cp := &controlclient.Client{BaseURL: m.ControlPlaneURL, Cache: cache, DeviceID: identity.ID, DeviceKey: key}
	// Installer/activation manifests may carry only ca_file: the control plane
	// is then verified by the same private CA, never by Windows system roots.
	cpCA := m.ControlPlaneCAFile
	if cpCA == "" {
		cpCA = m.CAFile
	}
	cp.HTTP, e = controlclient.HTTPSClient(cpCA)
	if e != nil {
		return e
	}
	target, e := netip.ParseAddrPort(m.ProbeTarget)
	if e != nil {
		return errors.New("explicit UDP echo probe target required")
	}
	c.mu.Lock()
	c.DiagnosticHTTPClient = cp.HTTP
	c.ControlPlaneURL = m.ControlPlaneURL
	c.TCPDiagnosticTarget = m.TCPProbeTarget
	c.NetworkHostRoutes = []netip.Addr{target.Addr()}
	c.mu.Unlock()
	trafficPath := ""
	if m.StateDirectory != "" {
		trafficPath = filepath.Join(m.StateDirectory, "traffic-usage.json")
	}
	c.traffic.Configure(trafficPath, identity.ID)
	if m.StateDirectory != "" {
		c.browser.youtube.configurePeerStore(filepath.Join(m.StateDirectory, "youtube-cdn-peer.json"), time.Now())
	}
	remote := &remoteState{controller: c, cp: cp, tls: cfg, target: target, addresses: make(map[string]string), clients: make(map[string]*transport.Pool)}
	if m.ProbeTokenFile != "" {
		remote.echoKey, e = e2eprobe.Token(m.ProbeTokenFile)
		if e != nil {
			return e
		}
	}
	if e = c.stopRemoteLocked(ctx); e != nil {
		return e
	}
	remoteCtx, stopRemote := context.WithCancel(c.ctx)
	c.remoteCancel = stopRemote
	done := make(chan struct{})
	c.remoteDone = done
	var workers sync.WaitGroup
	workers.Add(6)
	c.wg.Add(1)
	go func() { defer c.wg.Done(); defer workers.Done(); c.catalog.run(remoteCtx, cp, keys, m.StateDirectory) }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); defer workers.Done(); c.runSharedLearning(remoteCtx, cp, keys) }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); defer workers.Done(); c.runRemoteTraffic(remoteCtx, cp, keys) }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); defer workers.Done(); c.runSubscription(remoteCtx, cp) }()
	if m.StateDirectory != "" && c.updater.Load() == nil {
		u := newUpdater(keys, filepath.Dir(m.StateDirectory), launchUpdateSetup)
		u.relay = c.relayHTTPClient()
		c.updater.Store(u)
		c.wg.Add(1)
		go func() { defer c.wg.Done(); u.run(c.ctx) }()
	}
	renewer.fetch = cp.RenewCertificate
	c.wg.Add(1)
	go func() { defer c.wg.Done(); defer workers.Done(); renewer.run(remoteCtx) }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); workers.Wait(); close(done) }()
	signed, initialError := cp.Config(ctx)
	if initialError == nil {
		initialError = remote.apply(ctx, signed)
	}
	// Keep retrying after an initial outage; no valid config means DIRECT.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer workers.Done()
		defer remote.close()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-remoteCtx.Done():
				return
			case <-ticker.C:
				cfg, e := cp.Config(remoteCtx)
				if e == nil {
					remote.apply(remoteCtx, cfg)
				}
			}
		}
	}()
	return initialError
}

type remoteState struct {
	addresses  map[string]string
	echoKey    []byte
	controller *Controller
	cp         *controlclient.Client
	tls        *tls.Config
	target     netip.AddrPort
	clients    map[string]*transport.Pool
	version    uint64
}

func (s *remoteState) apply(ctx context.Context, cfg security.Config) error {
	c := s.controller
	for _, id := range cfg.RevokedDevices {
		if id == s.cp.DeviceID {
			c.activation.mu.Lock()
			c.activation.revoked = true
			c.activation.networkBlocked.Store(true)
			c.activation.status.State = "ACTIVATION_ERROR"
			c.activation.status.Error = "DEVICE_REVOKED"
			c.activation.mu.Unlock()
			cleanupErr := c.CleanupOwnedBrowserPolicies()
			c.activation.stopAutomatic.Store(true)
			c.mu.Lock()
			c.enabled = false
			c.mu.Unlock()
			if c.Backend != nil {
				_ = c.Backend.Stop()
			}
			s.close() // Revocation must still close sessions if registry access failed.
			if cleanupErr != nil {
				return fmt.Errorf("DEVICE_REVOKED_POLICY_CLEANUP: %w", cleanupErr)
			}
			return errors.New("device revoked")
		}
	}
	if cfg.Version != s.version {
		if e := c.Selector.Configure(cfg.RoutingParameters); e != nil {
			return e
		}
		c.activationMu.Lock()
		applyErr := func() (err error) {
			// The same public recovery authorization transaction applies to
			// signed remote profile updates, not only local IPC commands.
			if err = c.publishBrowserGuard(true); err != nil {
				return err
			}
			defer func() {
				if publicationErr := c.publishBrowserGuard(false); publicationErr != nil && err == nil {
					err = publicationErr
				}
			}()
			for _, p := range cfg.ApplicationProfiles {
				c.mu.Lock()
				_, local := c.localProfiles[p.ID]
				c.mu.Unlock()
				if !local {
					same := false
					for _, old := range c.Profiles.List() {
						if old.ID == p.ID {
							a, _ := json.Marshal(old)
							b, _ := json.Marshal(p)
							same = bytes.Equal(a, b)
						}
					}
					if !same {
						if e := c.reconfigure(p.ID, func() error {
							if err := c.Profiles.Upsert(p); err != nil {
								return err
							}
							c.syncPolicies()
							return nil
						}); e != nil {
							return e
						}
					}
				}
			}
			c.syncPolicies()
			return nil
		}()
		c.activationMu.Unlock()
		if applyErr != nil {
			return applyErr
		}
		s.version = cfg.Version
	}
	// Signed removals retire only that relay; other pools/flows remain independent.
	configured := map[string]bool{}
	for _, node := range cfg.Relays {
		configured[node.ID] = true
	}
	for id, pool := range s.clients {
		if !configured[id] {
			pool.Close()
			delete(s.clients, id)
			delete(s.addresses, id)
			c.Engine.SetRelay(id, nil)
			c.mu.Lock()
			delete(c.acceptanceRelays, id)
			delete(c.relayPools, id)
			delete(c.transportDrops, id)
			c.mu.Unlock()
		}
	}
	// Stable provider per relay; session creation/rotation stays inside its pool.
	for _, node := range cfg.Relays {
		node := node
		factory := func(ctx context.Context) (*transport.Client, error) {
			// Tickets are one-shot. Each factory invocation obtains a fresh signed
			// proof/ticket, including retries after an uncertain failed handshake.
			ticket, err := s.cp.Ticket(ctx, node.ID)
			if err != nil {
				if errors.Is(err, controlclient.ErrSubscriptionExpired) {
					c.subscriptionRecheck()
				}
				return nil, &transport.OpenError{Reason: "ticket_request_failed", Cause: err}
			}
			client, err := transport.DialWithTicket(ctx, node.Address, s.tls, ticket)
			if err != nil {
				return nil, &transport.OpenError{Reason: "session_auth_or_dial_failed", Cause: err}
			}
			client.StartRenewal(func(ctx context.Context) ([]byte, error) { return s.cp.Ticket(ctx, node.ID) })
			return client, nil
		}
		if pool := s.clients[node.ID]; pool != nil {
			pool.UpdateFactory(factory, s.addresses[node.ID] != node.Address)
			s.addresses[node.ID] = node.Address
			continue
		}
		pool, err := transport.NewPool(c.ctx, transport.DefaultPoolConfig(), factory)
		if err != nil {
			return err
		}
		s.clients[node.ID] = pool
		s.addresses[node.ID] = node.Address
		c.Engine.SetRelay(node.ID, pool)
		generation := c.Selector.RegisterTransport(node.ID)
		c.mu.Lock()
		c.transportDrops[node.ID] = pool.DropSnapshot
		c.relayPools[node.ID] = pool
		c.acceptanceRelays[node.ID] = acceptanceRelaySource{session: pool, target: s.target, generation: generation}
		c.mu.Unlock()
		pool.SetFailureHandler(func(reason string) { c.Selector.ReportTransportFailure(node.ID, generation, reason, time.Now()) })
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = pool.Warm(attempt)
		cancel()
	}
	candidates := []measurement.Candidate{{Metadata: optimizer.RelayCandidate{ID: optimizer.Direct}, Target: s.target, Open: measurement.OpenDirect}}
	for _, node := range cfg.Relays {
		client := s.clients[node.ID]
		if client == nil {
			continue
		}
		candidates = append(candidates, measurement.Candidate{Metadata: node, Target: s.target, Open: client.OpenProbeDatagram, Load: node.Load})
	}
	if len(s.echoKey) > 0 {
		for i := range candidates {
			candidates[i].Open = e2eprobe.ProbeOpener(candidates[i].Open, s.echoKey)
		}
	}
	c.Measurements.SetCandidates(candidates)
	// P0 only: distinct server audience, existing local VPS-01 policy name.
	// No process/profile/manual policy rewrite or TCP replay is performed.
	primaryAddress := ""
	for _, node := range cfg.Relays {
		// Server aggregate session load is not this healthy pool's capacity.
		if node.ID == primaryRelayID {
			primaryAddress = node.Address
		}
	}
	standbyID := standbyCandidate(cfg.Relays)
	standbyAddress := s.addresses[standbyID]
	if primary := s.clients[primaryRelayID]; primary != nil && primaryAddress != "" {
		var standby primaryRelayPool
		if pool := s.clients[standbyID]; pool != nil {
			standby = pool
		}
		provider := &primaryRelayProvider{primary: primary, standby: standby, primaryAddress: primaryAddress, standbyAddress: standbyAddress, standbyID: standbyID, runtime: c.relayPrimary, quality: c.Selector.Qualities}
		c.relayPrimary.configure(provider, primaryAddress, standbyAddress)
		c.Engine.SetRelay("VPS-01", provider)
	} else {
		c.relayPrimary.configure(nil, primaryAddress, standbyAddress)
		if pool := s.clients["VPS-01"]; pool != nil {
			c.Engine.SetRelay("VPS-01", pool)
		} else {
			c.Engine.SetRelay("VPS-01", nil)
		}
	}
	return nil
}
func (s *remoteState) close() {
	for _, pool := range s.clients {
		pool.Close()
	}
	s.clients = make(map[string]*transport.Pool)
}

// Caller holds remoteMu. Stop both old config polling and leaf renewal before
// replacing the identity/certificate so an old renewal cannot overwrite it.
func (c *Controller) stopRemoteLocked(ctx context.Context) error {
	if c.remoteCancel != nil {
		c.remoteCancel()
	}
	if c.remoteDone != nil {
		select {
		case <-c.remoteDone:
		case <-ctx.Done():
			return errors.New("previous connection shutdown pending")
		}
	}
	return nil
}
