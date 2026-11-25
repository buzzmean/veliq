package clientservice

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/gameudp"
	wp "github.com/buzzmean/veliq/platform/windows"
)

const (
	cs2ConsoleMaxBatch = 128 * 1024
	cs2ConsoleMaxLine  = 4096
	cs2ConsoleMaxAge   = 8 * time.Second
)

type cs2ConsoleAttempt struct {
	target                        netip.AddrPort
	start, ingame, peerTimeout    time.Time
	serverAccepted, peerResponded bool
	repliesAtEntry                uint64
	entryFlow                     uint64
}

// Owned by the game watcher. The cursor starts at EOF and never exports log text.
type cs2ConsoleObserver struct {
	engine     *gameudp.Engine
	network    string
	generation uint64
	file       os.FileInfo
	offset     int64
	fragment   []byte
	discard    bool
	tail       []byte
	polled     time.Time
	attempt    cs2ConsoleAttempt
}

func (c *Controller) observeCS2Console(o *cs2ConsoleObserver, now time.Time) {
	c.games.mu.Lock()
	var engine *gameudp.Engine
	var exe string
	for _, g := range c.games.items {
		if g.CS2Auto && g.Engine.Ready() {
			if engine != nil {
				engine = nil // two active profiles cannot share a console outcome
				break
			}
			engine, exe = g.Engine, g.Path
		}
	}
	c.games.mu.Unlock()
	status := "INACTIVE"
	network := c.gameMeasurementNetwork()
	if engine != nil && network != "" && strings.HasSuffix(gameudp.Canonical(exe), "/game/bin/win64/cs2.exe") {
		snapshot := engine.Snapshot()
		if o.engine != engine || o.network != network || o.generation != snapshot.Generation {
			*o = cs2ConsoleObserver{engine: engine, network: network, generation: snapshot.Generation}
		}
		record := func(out gameudp.CS2Outcome, _ time.Time) error {
			return engine.RecordCS2Outcome(out, time.Now())
		}
		root := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
		status = o.poll(root, now, func(line string) {
			o.line(line, now, snapshot.Flows, exe, c.discovery, record)
		})
		if status == "WATCHING" {
			o.confirm(now, snapshot.Flows, exe, c.discovery, record)
		}
	} else {
		*o = cs2ConsoleObserver{}
	}
	c.games.mu.Lock()
	c.games.consoleStatus = status
	c.games.mu.Unlock()
}

// A new file, replacement, truncate-and-refill, long pause or oversized batch
// invalidates the attempt. Keep a small byte anchor to detect same-inode rewrites.
func (o *cs2ConsoleObserver) poll(root string, now time.Time, line func(string)) string {
	file, err := os.OpenInRoot(root, filepath.Join("csgo", "console.log"))
	if err != nil {
		o.file = nil
		o.attempt = cs2ConsoleAttempt{}
		return "WAITING_FOR_CONSOLE"
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		o.file = nil
		o.attempt = cs2ConsoleAttempt{}
		return "WAITING_FOR_CONSOLE"
	}
	reset := o.file == nil || !os.SameFile(o.file, info) || info.Size() < o.offset ||
		info.Size()-o.offset > cs2ConsoleMaxBatch || now.Sub(o.polled) > cs2ConsoleMaxAge
	if !reset && len(o.tail) != 0 {
		check := make([]byte, len(o.tail))
		_, err = file.ReadAt(check, o.offset-int64(len(check)))
		reset = err != nil || !bytes.Equal(check, o.tail)
	}
	o.file, o.polled = info, now
	if reset {
		o.offset = info.Size()
		o.attempt = cs2ConsoleAttempt{}
		o.fragment, o.discard = nil, false
		o.tail = make([]byte, min(o.offset, 64))
		if _, err := file.ReadAt(o.tail, o.offset-int64(len(o.tail))); err != nil {
			o.file = nil
			return "WAITING_FOR_CONSOLE"
		}
		o.discard = len(o.tail) != 0 && o.tail[len(o.tail)-1] != '\n'
		return "WATCHING"
	}
	if info.Size() == o.offset {
		return "WATCHING"
	}
	data := make([]byte, info.Size()-o.offset)
	if _, err := file.ReadAt(data, o.offset); err != nil {
		o.file = nil
		o.attempt = cs2ConsoleAttempt{}
		return "WAITING_FOR_CONSOLE"
	}
	o.offset = info.Size()
	buf := append(o.tail, data...)
	o.tail = append([]byte(nil), buf[max(0, len(buf)-64):]...)
	for len(data) != 0 {
		part, rest, complete := bytes.Cut(data, []byte{'\n'})
		if len(part)+len(o.fragment) > cs2ConsoleMaxLine {
			o.discard = true
			o.fragment = nil
		}
		if !o.discard {
			o.fragment = append(o.fragment, part...)
		}
		if complete {
			if !o.discard {
				line(strings.TrimSuffix(string(o.fragment), "\r"))
			}
			o.fragment, o.discard = nil, false
		}
		data = rest
	}
	return "WATCHING"
}

func cs2ConsoleMessage(line string, now time.Time) (string, time.Time) {
	const layout = "2006/01/02 15:04:05"
	if len(line) < 15 || line[2] != '/' || line[5] != ' ' || line[14] != ' ' {
		return line, now // the continuously tailed, timestamp-free -condebug format
	}
	for _, year := range []int{now.Year(), now.Year() - 1, now.Year() + 1} {
		stamp, err := time.ParseInLocation(layout, strconv.Itoa(year)+"/"+line[:14], now.Location())
		if err == nil && now.Sub(stamp) <= cs2ConsoleMaxAge && stamp.Sub(now) <= time.Second {
			return line[15:], stamp
		}
	}
	return "", time.Time{}
}

// Only engine-generated connection lines can establish an endpoint. Chat,
// map names, byte counts, and the text of a console 'connect' command cannot.
func cs2ConnectLine(msg string) (endpoint netip.AddrPort, accepted bool, recognized bool) {
	var target string
	switch {
	case strings.HasPrefix(msg, "[Client] Received S2C_CONNECTION from "):
		target = strings.TrimPrefix(msg, "[Client] Received S2C_CONNECTION from ")
		accepted = true
	case strings.HasPrefix(msg, "[Client] Received S2C_CHALLENGE ["):
		_, target, _ = strings.Cut(msg, "] from ")
	case strings.HasPrefix(msg, "[Client] Sending C2S_CONNECT ["):
		_, target, _ = strings.Cut(msg, "] to ")
	case strings.HasPrefix(msg, "[Client] CL:"):
		rest := strings.TrimSpace(strings.TrimPrefix(msg, "[Client] CL:"))
		if strings.HasPrefix(rest, "Connected to ") {
			target, accepted = strings.TrimPrefix(rest, "Connected to "), true
		} else if strings.HasPrefix(rest, "Connecting to ") {
			target = strings.TrimPrefix(rest, "Connecting to ")
		} else {
			return endpoint, false, false
		}
	default:
		return endpoint, false, false
	}
	target, _, _ = strings.Cut(target, " ")
	endpoint, _ = netip.ParseAddrPort(strings.Trim(target, "'\""))
	return endpoint, accepted, true
}

// The server may never send a challenge. Its exact transport timeout plus a
// client-side sign-on failure can still identify that particular join.
func cs2TimedOutPeer(msg string) netip.AddrPort {
	header, _, ok := strings.Cut(msg, " 'server'] Timed out.")
	if !ok || !strings.HasPrefix(header, "[SteamNetSockets] [#") {
		return netip.AddrPort{}
	}
	_, peer, ok := strings.Cut(header, " UDP ")
	if !ok {
		return netip.AddrPort{}
	}
	if i := strings.LastIndexByte(peer, '@'); i >= 0 {
		peer = peer[i+1:]
	}
	dst, _ := netip.ParseAddrPort(peer)
	return dst
}

type cs2RecordFunc func(gameudp.CS2Outcome, time.Time) error

func (o *cs2ConsoleObserver) line(raw string, now time.Time, flows []gameudp.Evidence, exe string, discovery wp.Discovery, record cs2RecordFunc) {
	msg, stamp := cs2ConsoleMessage(raw, now)
	if dst, accepted, connection := cs2ConnectLine(msg); connection {
		responded := accepted || strings.HasPrefix(msg, "[Client] Received S2C_CHALLENGE [") || strings.HasPrefix(msg, "[Client] Sending C2S_CONNECT [")
		if !gameudp.Eligible(exe, exe, "udp", dst) {
			o.attempt = cs2ConsoleAttempt{}
		} else if o.attempt.target != dst || !o.attempt.ingame.IsZero() {
			o.attempt = cs2ConsoleAttempt{target: dst, start: stamp, serverAccepted: accepted, peerResponded: responded}
		} else {
			o.attempt.serverAccepted = o.attempt.serverAccepted || accepted
			o.attempt.peerResponded = o.attempt.peerResponded || responded
		}
		return
	}
	a := &o.attempt
	if !a.target.IsValid() {
		dst := cs2TimedOutPeer(msg)
		if !gameudp.Eligible(exe, exe, "udp", dst) {
			return
		}
		// This branch has no connection-start line. Require a single observed
		// launch in the last minute and its actual terminal sign-on error.
		var start time.Time
		for _, f := range flows {
			if f.Destination == dst.String() && f.Network == o.network && gameudp.Canonical(f.Application) == gameudp.Canonical(exe) &&
				f.Started.Before(now) && now.Sub(f.Started) <= time.Minute {
				if !start.IsZero() {
					return
				}
				start = f.Started
			}
		}
		if !start.IsZero() {
			*a = cs2ConsoleAttempt{target: dst, start: start, peerTimeout: stamp}
		}
		return
	}
	if stamp.Before(a.start) {
		return
	}
	if dst := cs2TimedOutPeer(msg); dst.IsValid() && dst == a.target && !a.peerResponded {
		a.peerTimeout = stamp
		return
	}
	if msg == "ChangeGameUIState: CSGO_GAME_UI_STATE_LOADINGSCREEN -> CSGO_GAME_UI_STATE_INGAME" && a.serverAccepted && a.ingame.IsZero() {
		if f, ok := o.flow(flows, exe, discovery, now); ok {
			a.ingame, a.entryFlow, a.repliesAtEntry = stamp, f.ID, f.Replies
		}
		return
	}
	var reason string
	switch {
	case strings.HasPrefix(msg, "[Client] Disconnection during connection phase. Sign-on state: "):
		_, reason, _ = strings.Cut(msg, " Disconnect reason: ")
	case strings.HasPrefix(msg, "[Client] Disconnected from server: "):
		reason = strings.TrimPrefix(msg, "[Client] Disconnected from server: ")
	case strings.HasPrefix(msg, "ChangeGameUIState: ") && strings.HasSuffix(msg, " -> CSGO_GAME_UI_STATE_MAINMENU"):
		o.attempt = cs2ConsoleAttempt{}
		return
	default:
		return
	}
	outcome := "UNKNOWN"
	switch strings.TrimSuffix(reason, ".") {
	case "NETWORK_DISCONNECT_TIMEDOUT":
		// A timeout of a fully signed-on match is not a failed join.
		signOnError := strings.HasPrefix(msg, "[Client] Disconnection during connection phase. Sign-on state: ")
		if !strings.Contains(msg, "(SIGNONSTATE_FULL)") && (a.peerTimeout.IsZero() ||
			signOnError && stamp.Sub(a.peerTimeout) >= 0 && stamp.Sub(a.peerTimeout) <= 3*time.Second) {
			outcome = "TIMEOUT"
		}
	case "NETWORK_DISCONNECT_REJECT_SERVERFULL":
		outcome = "FULL"
	default:
		if strings.HasPrefix(reason, "NETWORK_DISCONNECT_REJECT_") || strings.HasPrefix(reason, "NETWORK_DISCONNECT_KICKED") || strings.HasPrefix(reason, "NETWORK_DISCONNECT_BANNED") {
			outcome = "DENIED"
		}
	}
	if f, ok := o.flow(flows, exe, discovery, now); ok {
		o.report(f, outcome, cs2SignonPhase(msg, *a, f), now, record)
	}
	o.attempt = cs2ConsoleAttempt{}
}

// An archived trace briefly entered the in-game UI despite a full server.
// Require continuing inbound game traffic on the same flow after that screen.
func (o *cs2ConsoleObserver) confirm(now time.Time, flows []gameudp.Evidence, exe string, discovery wp.Discovery, record cs2RecordFunc) {
	a := o.attempt
	if !a.target.IsValid() {
		return
	}
	if now.Sub(a.start) > 10*time.Minute {
		o.attempt = cs2ConsoleAttempt{}
		return
	}
	if a.ingame.IsZero() || now.Sub(a.ingame) < 15*time.Second {
		return
	}
	f, ok := o.flow(flows, exe, discovery, now)
	if ok && f.ID == a.entryFlow && f.Replies > a.repliesAtEntry && now.Sub(f.LastReply) <= 2*time.Second && now.Sub(f.LastOutgoing) <= 2*time.Second {
		if o.report(f, "JOINED", "INGAME", now, record) == nil {
			o.attempt = cs2ConsoleAttempt{}
		}
	}
}

func (o *cs2ConsoleObserver) flow(flows []gameudp.Evidence, exe string, discovery wp.Discovery, now time.Time) (gameudp.Evidence, bool) {
	var selected gameudp.Evidence
	for _, f := range flows {
		if f.Network != o.network || gameudp.Canonical(f.Application) != gameudp.Canonical(exe) || f.Destination != o.attempt.target.String() ||
			f.ID == 0 || f.Outgoing == 0 || f.Started.Before(o.attempt.start.Add(-8*time.Second)) ||
			now.Sub(f.LastOutgoing) > 30*time.Second {
			continue
		}
		// A second native socket may have appeared between the first sign-on
		// line and the error. An old socket cannot claim the new one's result.
		if selected.ID != 0 || f.Started.After(o.attempt.start.Add(2*time.Second)) {
			return gameudp.Evidence{}, false
		}
		selected = f
	}
	if selected.ID == 0 || discovery == nil {
		return gameudp.Evidence{}, false
	}
	live, err := discovery.Lookup(selected.PID)
	ok := err == nil && live.PID == selected.PID && live.CreationTime == selected.Birth && gameudp.Canonical(live.Path) == gameudp.Canonical(exe)
	return selected, ok
}

func cs2SignonPhase(msg string, a cs2ConsoleAttempt, f gameudp.Evidence) string {
	const prefix = "[Client] Disconnection during connection phase. Sign-on state: "
	early := false
	if rest, ok := strings.CutPrefix(msg, prefix); ok {
		if end, _, ok := strings.Cut(rest, "). Disconnect reason: "); ok {
			_, state, _ := strings.Cut(end, " (")
			switch state {
			case "SIGNONSTATE_NONE", "SIGNONSTATE_CHALLENGE":
				early = true
			case "SIGNONSTATE_CONNECTED", "SIGNONSTATE_NEW", "SIGNONSTATE_PRESPAWN", "SIGNONSTATE_SPAWN", "SIGNONSTATE_FULL", "SIGNONSTATE_CHANGELEVEL":
				return state
			}
		}
	}
	if a.serverAccepted {
		return "SERVER_ACCEPTED"
	}
	if a.peerResponded || f.Replies != 0 {
		return "TRANSPORT_ONLY"
	}
	// Zero capture counters alone cannot authorize a new local socket. The
	// game must also report an early sign-on failure or exact-peer timeout.
	if early || !a.peerTimeout.IsZero() {
		return "NO_REPLY_OBSERVED"
	}
	return ""
}

func (o *cs2ConsoleObserver) report(f gameudp.Evidence, outcome, phase string, now time.Time, record cs2RecordFunc) error {
	return record(gameudp.CS2Outcome{FlowID: f.ID, Started: f.Started, PID: f.PID, Birth: f.Birth,
		Destination: o.attempt.target, Outcome: outcome, Phase: phase}, now)
}
