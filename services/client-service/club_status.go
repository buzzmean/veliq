package clientservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/internal/e2eprobe"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

type clubConfiguration struct{ manifest Manifest }
type ClubRelayCheck struct {
	CheckedAt time.Time `json:"checked_at"`
	TCP       string    `json:"tcp"`
	UDP       string    `json:"udp"`
}
type ClubBrowserCheck struct {
	Profile   string `json:"profile"`
	State     string `json:"state"`
	Exchanges uint64 `json:"bidirectional_exchanges"`
}
type ClubGameCheck struct {
	Activity      string `json:"activity"`
	InitialPolicy string `json:"initial_policy"`
	Profile       string `json:"profile"`
	State         string `json:"state"`
	Sent          uint64 `json:"outgoing"`
	Received      uint64 `json:"incoming"`
	Fakes         uint64 `json:"fakes"`
}
type ClubStatus struct {
	Version         int                `json:"version"`
	At              time.Time          `json:"at"`
	Host            string             `json:"host"`
	Build           string             `json:"build"`
	PID             uint32             `json:"service_pid"`
	State           string             `json:"state"`
	Summary         string             `json:"summary"`
	Activation      string             `json:"activation"`
	ActivationError string             `json:"activation_error,omitempty"`
	Identity        bool               `json:"has_identity"`
	Connected       bool               `json:"connected"`
	Capture         bool               `json:"capture_active"`
	BackendReady    bool               `json:"backend_ready"`
	Relay           ClubRelayCheck     `json:"relay"`
	Browsers        []ClubBrowserCheck `json:"browsers"`
	Games           []ClubGameCheck    `json:"games"`
	PageResult      string             `json:"page_result"`
	GameResult      string             `json:"game_result"`
}

func (c *Controller) clubStatus() ClubStatus {
	s := c.Snapshot()
	a := c.activationStatus()
	n := c.nativeSnapshot()
	g := c.gameStatus()
	host, _ := os.Hostname()
	out := ClubStatus{Version: 1, At: time.Now().UTC(), Host: host, Build: s.Build, PID: s.ServicePID, Activation: a.State, ActivationError: a.Error, Identity: a.HasIdentity, Connected: s.Connected, Capture: s.CaptureActive, BackendReady: s.Backend.Ready, Browsers: []ClubBrowserCheck{}, Games: []ClubGameCheck{}, Relay: ClubRelayCheck{TCP: "NOT_CHECKED", UDP: "NOT_CHECKED"}, PageResult: "NOT_VERIFIED", GameResult: "NOT_VERIFIED"}
	if p := c.clubProbe.Load(); p != nil {
		out.Relay = *p
	}
	for _, p := range c.Profiles.List() {
		if !nativeBrowserProfile(p) {
			continue
		}
		v := ClubBrowserCheck{Profile: p.Name, State: "ARMED_NOT_OBSERVED"}
		if !n.Ready || !n.Enabled {
			v.State = "PENDING"
		}
		for _, q := range n.Profiles {
			if q.Profile == p.ID {
				v.Exchanges = q.NativeOnly.Exchanges
				if v.Exchanges > 0 {
					v.State = "BIDIRECTIONAL_NOT_PAGE_PROOF"
				}
			}
		}
		out.Browsers = append(out.Browsers, v)
	}
	for _, p := range g.Profiles {
		v := ClubGameCheck{Profile: p.Name, State: p.State, Activity: p.Activity, InitialPolicy: p.Engine.InitialPolicy}
		for _, f := range p.Engine.Flows {
			v.Sent += f.Outgoing
			v.Received += f.Replies
			v.Fakes += f.Fakes
		}
		out.Games = append(out.Games, v)
	}
	out.State = "PENDING"
	if !c.clubMode.Load() {
		out.State = "NOT_CLUB"
	} else if a.Error != "" {
		out.State = "ACTIVATION_ERROR"
	} else if a.HasIdentity && s.Connected && s.Optimizing && s.CaptureActive && s.Backend.Ready && len(out.Browsers) > 0 {
		out.State = "RUNTIME_READY_CHECK_PENDING"
		if out.Relay.TCP == "PASS" && out.Relay.UDP == "PASS" && time.Since(out.Relay.CheckedAt) < 6*time.Minute {
			out.State = "BASELINE_PASS_RUNTIME_UNVERIFIED"
		}
	}
	out.Summary = fmt.Sprintf("VELIQ %s activation=%s relay_tcp=%s relay_udp=%s browsers=%d games=%d pages=UNVERIFIED matches=UNVERIFIED", out.State, out.Activation, out.Relay.TCP, out.Relay.UDP, len(out.Browsers), len(out.Games))
	return out
}
func (c *Controller) watchClubStatus() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var jitter [1]byte
	_, _ = rand.Read(jitter[:])
	nextProbe := time.Now().Add(time.Duration(jitter[0]%30) * time.Second)
	for {
		cfg := c.clubConfig.Load()
		if cfg == nil {
			return
		}
		if c.relayConnected() && !time.Now().Before(nextProbe) {
			p := c.checkClubRelay(cfg.manifest)
			c.clubProbe.Store(&p)
			nextProbe = time.Now().Add(5 * time.Minute)
			if p.TCP != "PASS" || p.UDP != "PASS" {
				nextProbe = time.Now().Add(time.Duration(30+jitter[0]%30) * time.Second)
			}
		}
		if err := writeClubStatus(filepath.Join(filepath.Dir(cfg.manifest.DeviceIdentityFile), "club-status.json"), cfg.manifest.OwnerSID, c.clubStatus()); err != nil {
			slog.Warn("club status file unavailable", "code", "CLUB_STATUS_WRITE_FAILED")
		}
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func writeClubStatus(path, sid string, status ClubStatus) error {
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".club-status-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.Chmod(0600)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = wp.AllowOwnerReadFile(f.Name(), sid); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (c *Controller) checkClubRelay(m Manifest) ClubRelayCheck {
	out := ClubRelayCheck{CheckedAt: time.Now().UTC(), TCP: "NOT_AVAILABLE", UDP: "NOT_AVAILABLE"}
	key, err := e2eprobe.Token(m.ProbeTokenFile)
	if err != nil {
		return out
	}
	c.mu.Lock()
	pool := c.relayPools["VPS-01"]
	c.mu.Unlock()
	if pool == nil {
		return out
	}
	udp, ue := netip.ParseAddrPort(m.ProbeTarget)
	tcp, te := netip.ParseAddrPort(m.TCPProbeTarget)
	if ue == nil {
		ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
		out.UDP = clubUDPProof(ctx, pool.OpenProbeDatagram, udp, key)
		cancel()
	}
	if te == nil {
		ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
		out.TCP = clubTCPProof(ctx, pool.OpenTCP, tcp, key)
		cancel()
	}
	return out
}
func clubUDPProof(ctx context.Context, open func(context.Context, netip.AddrPort) (routing.Datagram, error), dst netip.AddrPort, key []byte) string {
	d, err := open(ctx, dst)
	if err != nil {
		return "OPEN_FAILED"
	}
	defer d.Close()
	packet := e2eprobe.Packet{Sequence: 1}
	if _, err = rand.Read(packet.Run[:]); err != nil {
		return "NONCE_FAILED"
	}
	if err = d.Send(e2eprobe.Encode(packet, key)); err != nil {
		return "SEND_FAILED"
	}
	raw, err := d.Receive(ctx)
	if err != nil {
		return "REPLY_TIMEOUT_OR_IO_FAILED"
	}
	return clubValidateEcho(raw, key, packet)
}
func clubTCPProof(ctx context.Context, open func(context.Context, netip.AddrPort) (net.Conn, error), dst netip.AddrPort, key []byte) string {
	d, err := open(ctx, dst)
	if err != nil {
		return "OPEN_FAILED"
	}
	defer d.Close()
	stop := context.AfterFunc(ctx, func() { d.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	d.SetDeadline(deadline)
	packet := e2eprobe.Packet{Sequence: 1}
	if _, err = rand.Read(packet.Run[:]); err != nil {
		return "NONCE_FAILED"
	}
	if _, err = io.Copy(d, bytes.NewReader(e2eprobe.Encode(packet, key))); err != nil {
		return "SEND_FAILED"
	}
	raw := make([]byte, e2eprobe.Size)
	if _, err = io.ReadFull(d, raw); err != nil {
		return "REPLY_TIMEOUT_OR_IO_FAILED"
	}
	return clubValidateEcho(raw, key, packet)
}
func clubValidateEcho(raw, key []byte, p e2eprobe.Packet) string {
	q, err := e2eprobe.Decode(raw, key)
	if err != nil || !q.Reply || q.Run != p.Run || q.Sequence != p.Sequence || !q.Peer.IsValid() {
		return "AUTHENTICATED_REPLY_INVALID"
	}
	return "PASS"
}
