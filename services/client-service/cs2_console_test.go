package clientservice

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/gameudp"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestCS2ConsoleOnlyReadsFreshCompleteLines(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "csgo")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "console.log")
	write := func(data string, flags int) {
		t.Helper()
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|flags, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(data); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var o cs2ConsoleObserver
	var observed []string
	now := time.Now()
	poll := func() string {
		now = now.Add(time.Second)
		return o.poll(root, now, func(s string) { observed = append(observed, s) })
	}
	if poll() != "WAITING_FOR_CONSOLE" {
		t.Fatal("missing console")
	}
	write("old event\nold partial", os.O_TRUNC)
	if poll() != "WATCHING" {
		t.Fatal("did not establish baseline")
	}
	write("continued\nnew", os.O_APPEND)
	poll()
	write(" event\r\n"+strings.Repeat("x", cs2ConsoleMaxLine+1), os.O_APPEND)
	poll()
	write("end\nsecond\n", os.O_APPEND)
	poll()
	poll()
	if !slices.Equal(observed, []string{"new event", "second"}) {
		t.Fatal(observed)
	}
	o.attempt.start = now
	write(strings.Repeat("replacement\n", 600), os.O_TRUNC) // same file, already larger than old EOF
	poll()
	if !o.attempt.start.IsZero() || len(observed) != 2 {
		t.Fatal("read pre-rotation evidence")
	}
	write("third\n", os.O_APPEND)
	poll()
	if !slices.Equal(observed, []string{"new event", "second", "third"}) {
		t.Fatal(observed)
	}
	now = now.Add(time.Minute)
	write("stale\n", os.O_APPEND)
	poll()
	if len(observed) != 3 {
		t.Fatal("read stale buffered event")
	}
}

func TestCS2ConsoleMatchesOnlyCurrentGameJoin(t *testing.T) {
	const (
		exe         = "C:/Steam/CS/game/bin/win64/cs2.exe"
		target      = "192.0.2.31:27015"
		connect     = "[Client] Received S2C_CONNECTION from " + target + " [addons:'2']"
		ingame      = "ChangeGameUIState: CSGO_GAME_UI_STATE_LOADINGSCREEN -> CSGO_GAME_UI_STATE_INGAME"
		timeout     = "[Client] Disconnection during connection phase. Sign-on state: 2 (SIGNONSTATE_CONNECTED). Disconnect reason: NETWORK_DISCONNECT_TIMEDOUT."
		full        = "[Client] Disconnection during connection phase. Sign-on state: 5 (SIGNONSTATE_SPAWN). Disconnect reason: NETWORK_DISCONNECT_REJECT_SERVERFULL."
		peerTimeout = "[SteamNetSockets] [#123 UDP steamid:fixture@" + target + " 'server'] Timed out.  10000ms"
	)
	for _, tc := range []struct {
		name    string
		lines   []string
		seconds []int
		mutate  string
		want    string
	}{
		{"signon_timeout", []string{connect, timeout}, []int{0, 11}, "", "TIMEOUT"},
		{"no_challenge_but_exact_peer", []string{peerTimeout, timeout}, []int{11, 11}, "", "TIMEOUT"},
		{"unbound_generic_timeout", []string{timeout}, []int{4}, "", ""},
		{"lookalike_chat", []string{"[Chat] " + connect, timeout}, []int{0, 11}, "", ""},
		{"local_transition_resets", []string{connect, "[Client] CL:  Connected to 'loopback:1'", timeout}, []int{0, 2, 11}, "", ""},
		{"full_after_ui", []string{connect, ingame, full}, []int{0, 1, 2}, "", "FULL"},
		{"explicit_denial", []string{connect, "[Client] Disconnected from server: NETWORK_DISCONNECT_REJECT_PASSWORD"}, []int{0, 1}, "", "DENIED"},
		{"unknown_reason", []string{connect, "[Client] Disconnected from server: NETWORK_DISCONNECT_SOMETHING_NEW"}, []int{0, 2}, "", "UNKNOWN"},
		{"ui_without_play", []string{connect, ingame}, []int{0, 1}, "", ""},
		{"ui_and_continuing_traffic", []string{connect, ingame}, []int{0, 1}, "continue", "JOINED"},
		{"wrong_network", []string{connect, timeout}, []int{0, 11}, "network", ""},
		{"pid_reuse", []string{connect, timeout}, []int{0, 11}, "birth", ""},
		{"two_matching_flows", []string{connect, timeout}, []int{0, 11}, "overlap", ""},
		{"socket_changed_mid_signon", []string{connect, timeout}, []int{0, 11}, "later-flow", ""},
		{"different_peer", []string{connect, timeout}, []int{0, 11}, "peer", ""},
		{"stale_console_time", []string{"11/07 20:30:00 " + connect, timeout}, []int{0, 11}, "", ""},
		{"multiline_duplicate", []string{connect, timeout, "[Client] Disconnected from server: NETWORK_DISCONNECT_TIMEDOUT"}, []int{0, 11, 11}, "", "TIMEOUT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 11, 7, 21, 30, 0, 0, time.Local)
			identity := wp.ProcessIdentity{PID: 11, CreationTime: 100, Path: exe}
			o := cs2ConsoleObserver{network: "network"}
			f := gameudp.Evidence{ID: 4, PID: 11, Birth: 100, Application: exe, Destination: target, Network: "network", Started: start, LastOutgoing: start, LastReply: start, Outgoing: 4, Replies: 2}
			flows := []gameudp.Evidence{f}
			switch tc.mutate {
			case "network":
				flows[0].Network = "other"
			case "birth":
				identity.CreationTime++
			case "peer":
				flows[0].Destination = "192.0.2.32:27015"
			case "later-flow":
				f.ID++
				f.Started = start.Add(5 * time.Second)
				f.LastOutgoing = f.Started
				flows = append(flows, f)
			case "overlap":
				f.ID++
				flows = append(flows, f)
			}
			owners := &groupDiscovery{[]wp.ProcessIdentity{identity}}
			var records []gameudp.CS2Outcome
			record := func(r gameudp.CS2Outcome, now time.Time) error { records = append(records, r); return nil }
			for i, s := range tc.lines {
				now := start.Add(time.Duration(tc.seconds[i]) * time.Second)
				o.line(s, now, flows, exe, owners, record)
				o.confirm(now, flows, exe, owners, record)
			}
			now := start.Add(19 * time.Second)
			if tc.mutate == "continue" {
				flows[0].Replies++
				flows[0].LastOutgoing, flows[0].LastReply = now, now
			}
			o.confirm(now, flows, exe, owners, record)
			o.confirm(now.Add(time.Second), flows, exe, owners, record)
			if tc.want == "" {
				if len(records) != 0 {
					t.Fatal(records)
				}
			} else if len(records) != 1 || records[0].Outcome != tc.want || records[0].FlowID != 4 || records[0].Destination.String() != target || records[0].Quality != nil {
				t.Fatal(tc.want, records)
			}
			if len(records) > 0 {
				switch tc.want {
				case "JOINED":
					if records[0].Phase != "INGAME" {
						t.Fatal(records[0])
					}
				case "TIMEOUT":
					if records[0].Phase != "SIGNONSTATE_CONNECTED" {
						t.Fatal(records[0])
					}
				case "FULL":
					if records[0].Phase != "SIGNONSTATE_SPAWN" {
						t.Fatal(records[0])
					}
				}
			}
		})
	}
}

func TestCS2ConsoleWatcherPublishesMatchedNativeTimeout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "game")
	if err := os.MkdirAll(filepath.Join(root, "csgo"), 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "csgo", "console.log")
	if err := os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(root, "bin", "win64", "cs2.exe")
	id := wp.ProcessIdentity{PID: 12, CreationTime: 23, Path: exe}
	network := strings.Repeat("b", 64)
	now := time.Now()
	engine := gameudp.New()
	engine.SetCS2Auto(true)
	engine.Configure(exe, true)
	engine.SetNetwork(network)
	engine.SetReason("")
	c := &Controller{discovery: &groupDiscovery{[]wp.ProcessIdentity{id}}}
	c.network.Store(&wp.NetworkContext{Fingerprint: network, ObservedAt: now})
	c.games.items = map[string]*gameEntry{"cs2": {CS2Auto: true, Path: exe, Engine: engine}}
	var watcher cs2ConsoleObserver
	c.observeCS2Console(&watcher, now.Add(-3*time.Second))
	if c.games.consoleStatus != "WATCHING" {
		t.Fatal(c.games.consoleStatus)
	}
	k := gameudp.Key{Application: exe, Network: network, PID: id.PID, Birth: id.CreationTime, Source: netip.MustParseAddrPort("127.0.0.1:51000"), Destination: netip.MustParseAddrPort("192.0.2.7:27015")}
	f, err := engine.Open(k, now.Add(-2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	engine.Outgoing(f, 64, now.Add(-2*time.Second))
	engine.Reply(f, 32, now.Add(-time.Second))
	lines := "[Client] Received S2C_CONNECTION from 192.0.2.7:27015\n[Client] Disconnection during connection phase. Sign-on state: 2 (SIGNONSTATE_CONNECTED). Disconnect reason: NETWORK_DISCONNECT_TIMEDOUT.\n"
	if err := os.WriteFile(name, []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	c.observeCS2Console(&watcher, now)
	got := engine.Evidence(f)
	if got.JoinOutcome != "TIMEOUT" || got.JoinPhase != "SIGNONSTATE_CONNECTED" || got.Stage != gameudp.Direct || got.GameQuality != nil {
		t.Fatal(got)
	}
}

func TestCS2EarlyTimeoutRequiresGameAndTransportEvidence(t *testing.T) {
	const peer = "192.0.2.17:27015"
	const early = "[Client] Disconnection during connection phase. Sign-on state: 1 (SIGNONSTATE_CHALLENGE). Disconnect reason: NETWORK_DISCONNECT_TIMEDOUT."
	const connected = "[Client] Disconnection during connection phase. Sign-on state: 2 (SIGNONSTATE_CONNECTED). Disconnect reason: NETWORK_DISCONNECT_TIMEDOUT."
	const exe = "D:/Steam/game/bin/win64/cs2.exe"
	tests := []struct {
		name, first, terminal string
		replies               uint64
		phase                 string
	}{
		{"early_with_zero_replies", "[Client] CL: Connecting to '" + peer + "'", early, 0, "NO_REPLY_OBSERVED"},
		{"no_challenge_line", "[SteamNetSockets] [#82 UDP " + peer + " 'server'] Timed out. 10001ms", early, 0, "NO_REPLY_OBSERVED"},
		{"capture_received_packet", "[Client] CL: Connecting to '" + peer + "'", early, 1, "TRANSPORT_ONLY"},
		{"game_received_challenge", "[Client] Received S2C_CHALLENGE [0 auth 3] from " + peer, early, 0, "TRANSPORT_ONLY"},
		{"game_accepted_peer", "[Client] Received S2C_CONNECTION from " + peer, early, 0, "SERVER_ACCEPTED"},
		{"signon_already_connected", "[Client] CL: Connecting to '" + peer + "'", connected, 0, "SIGNONSTATE_CONNECTED"},
		{"unknown_stage", "[Client] CL: Connecting to '" + peer + "'", "[Client] Disconnected from server: NETWORK_DISCONNECT_TIMEDOUT", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			o := cs2ConsoleObserver{network: "n"}
			flows := []gameudp.Evidence{{ID: 1, Started: now.Add(-time.Second), PID: 11, Birth: 21, Application: exe, Network: "n", Destination: peer, Outgoing: 1, Replies: tc.replies, LastOutgoing: now}}
			discovery := &groupDiscovery{[]wp.ProcessIdentity{{PID: 11, CreationTime: 21, Path: exe}}}
			var reported []gameudp.CS2Outcome
			record := func(out gameudp.CS2Outcome, _ time.Time) error { reported = append(reported, out); return nil }
			o.line(tc.first, now, flows, exe, discovery, record)
			o.line(tc.terminal, now.Add(time.Second), flows, exe, discovery, record)
			if len(reported) != 1 || reported[0].Outcome != "TIMEOUT" || reported[0].Phase != tc.phase {
				t.Fatal(reported)
			}
		})
	}
}
