package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/protocol"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/traffic"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/releaseinfo"
	"github.com/buzzmean/veliq/services/relay"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", ":4433", "QUIC UDP listener")
	cert := flag.String("cert", "", "server certificate PEM")
	key := flag.String("key", "", "server key PEM")
	ca := flag.String("ca", "", "device CA PEM")
	metrics := flag.String("metrics", "127.0.0.1:9090", "local health/metrics address")
	allow := flag.String("allow-cidrs", "", "explicit destination allowlist (comma-separated); default public only")
	relayID := flag.String("relay-id", "", "ticket audience (enables ticket-required ALPN)")
	ticketKeys := flag.String("ticket-keys", "", "out-of-band Ed25519 trust JSON")
	replayFile := flag.String("replay-cache", "relay-state/replay.json", "persistent replay cache")
	cpURL := flag.String("control-plane", "", "signed config/revocation endpoint")
	trafficState := flag.String("traffic-state-file", "", "optional persistent NIC monthly accounting; disabled when empty")
	trafficInterface := flag.String("traffic-interface", "", "optional Linux egress NIC (default IPv4 route when empty)")
	heartbeatFile := flag.String("heartbeat-token-file", "", "relay-specific heartbeat token")
	allowHTTP := flag.Bool("allow-http-development", false, "allow HTTP on isolated development network")
	cpCA := flag.String("control-plane-ca", "", "explicit private TLS CA for control plane")
	fleetMode := flag.Bool("fleet-admission", false, "require signed fleet admission before accepting new sessions or streams")
	fleetObserve := flag.Bool("fleet-observe-only", false, "report scoped measurements without changing legacy admission")
	version := flag.Bool("version-json", false, "print build and upgrade capabilities without opening credentials or listeners")
	flag.Parse()
	if *version {
		if err := releaseinfo.Write(os.Stdout, "relay", []string{protocol.TicketALPN, protocol.LeaseALPN}, security.MaxConfigDocument, 1800); err != nil {
			os.Exit(1)
		}
		return
	}
	fail := func(e error) { slog.Error("relay startup failed", "error", e); os.Exit(1) }
	t, e := transport.TLS(*cert, *key, *ca, true)
	if e != nil {
		fail(e)
	}
	var prefixes []netip.Prefix
	if *allow != "" {
		for _, s := range strings.Split(*allow, ",") {
			p, e := netip.ParsePrefix(s)
			if e != nil {
				fail(e)
			}
			prefixes = append(prefixes, p)
		}
	}
	var verifier *security.TicketVerifier
	var fleetGate *relay.FleetAdmission
	var cp *controlclient.Client
	var heartbeat string
	if *relayID != "" {
		raw, e := os.ReadFile(*ticketKeys)
		if e != nil {
			fail(e)
		}
		var encoded map[string]string
		if e = json.Unmarshal(raw, &encoded); e != nil {
			fail(e)
		}
		keys := map[string]ed25519.PublicKey{}
		for id, value := range encoded {
			k, e := security.DecodePublicKey(value)
			if e != nil {
				fail(e)
			}
			keys[id] = k
		}
		if *fleetMode {
			fleetGate, e = relay.NewFleetAdmission(*relayID, keys)
			if e != nil {
				fail(e)
			}
		}
		verifier, e = security.NewPersistentTicketVerifier(keys, *relayID, *replayFile)
		if e != nil {
			fail(e)
		}
		if *cpURL != "" {
			cache := security.NewConfigCache(keys, filepath.Join(filepath.Dir(*replayFile), "signed-config.json"))
			_ = cache.Load(time.Now())
			cp = &controlclient.Client{BaseURL: *cpURL, Cache: cache, AllowHTTPDevelopment: *allowHTTP}
			if *cpCA != "" {
				cp.HTTP, e = controlclient.HTTPSClient(*cpCA)
				if e != nil {
					fail(e)
				}
			}
		}
	}
	if *heartbeatFile != "" {
		raw, e := os.ReadFile(*heartbeatFile)
		if e != nil {
			fail(e)
		}
		heartbeat = strings.TrimSpace(string(raw))
	}
	if (*fleetMode || *fleetObserve) && (*relayID == "" || cp == nil || *cpCA == "" ||
		!strings.HasPrefix(*cpURL, "https://") || len(heartbeat) != 32) {
		fail(errors.New("fleet requires relay audience, pinned HTTPS control plane, and node-specific heartbeat credential"))
	}
	r, e := relay.Listen(*addr, relay.Config{TLS: t, Allow: prefixes, TicketVerifier: verifier,
		Fleet: fleetGate, FleetObserve: *fleetObserve})
	if e != nil {
		fail(e)
	}
	background, cancelBackground := context.WithCancel(context.Background())
	defer cancelBackground()
	if fleetGate != nil || *fleetObserve {
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				now := time.Now().UTC()
				sampled, valid := r.FleetSample(now)
				var applied uint64
				if fleetGate != nil {
					applied = fleetGate.Version()
				}
				req, cancel := context.WithTimeout(background, 5*time.Second)
				raw, err := cp.FleetHeartbeat(req, security.FleetHeartbeat{
					ID: *relayID, Sequence: uint64(now.UnixNano()), AppliedVersion: applied,
					Sampled: valid, Used: sampled, ObserveOnly: *fleetObserve,
				}, heartbeat)
				cancel()
				if err == nil && fleetGate != nil {
					_ = fleetGate.Apply(raw, time.Now())
				}
				select {
				case <-background.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	var latestTraffic atomic.Pointer[traffic.Observation]
	if *trafficState != "" {
		tally, err := traffic.NewMonth(*trafficState)
		if err != nil {
			slog.Warn("optional traffic accounting unavailable; routing unchanged", "code", "TRAFFIC_STATE_LOAD_FAILED")
		} else {
			limit := uint64(0)
			if *relayID == "VPS-PRIMARY" {
				limit = 3000000000000
			}
			r.Traffic = func() []traffic.MonthRow { return tally.Snapshot(time.Now()) }
			go func() {
				timer := time.NewTicker(5 * time.Second)
				defer timer.Stop()
				for {
					now := time.Now()
					o, e := traffic.ReadInterface(*relayID, *trafficInterface, now)
					if e == nil {
						if e = tally.Observe(o, limit, now); e == nil {
							latestTraffic.Store(&o)
						}
					}
					select {
					case <-background.Done():
						return
					case <-timer.C:
					}
				}
			}()
		}
	}
	if cp != nil {
		go func() {
			tick := time.NewTicker(30 * time.Second)
			defer tick.Stop()
			for {
				request, stop := context.WithTimeout(background, 5*time.Second)
				cfg, e := cp.Config(request)
				if e == nil {
					keys := map[string]ed25519.PublicKey{}
					for id, value := range cfg.PublicKeys {
						k, e := security.DecodePublicKey(value)
						if e == nil {
							keys[id] = k
						}
					}
					verifier.Update(keys, cfg.RevokedDevices)
				}
				if heartbeat != "" {
					if fleetGate == nil {
						_ = cp.Heartbeat(request, *relayID, heartbeat, float64(r.Metrics.Sessions.Load())/128)
					}
					if o := latestTraffic.Load(); o != nil {
						_ = cp.RelayTraffic(request, heartbeat, *o)
					}
				}
				stop()
				select {
				case <-background.Done():
					return
				case <-tick.C:
				}
			}
		}()
	}
	h := &http.Server{Addr: *metrics, Handler: r.Handler(), ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if e := h.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			slog.Error("metrics listener failed", "error", e)
		}
	}()
	slog.Info("relay listening", "address", r.Addr().String())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h.Shutdown(ctx)
}
