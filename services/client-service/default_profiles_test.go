package clientservice

import (
	"context"
	"net/netip"
	"testing"

	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func destTuple(proto, addr string, port uint16) wp.Tuple {
	return wp.Tuple{Protocol: proto, Source: netip.MustParseAddrPort("192.0.2.1:55000"), Destination: netip.AddrPortFrom(netip.MustParseAddr(addr), port)}
}

// A clean install must cover the blocked desktop apps without any manual profile.
// Packaged apps live in versioned WindowsApps folders, so matching is by exe name.
func TestBuiltInProfilesRouteBlockedDesktopAppsRelayFirstFailClosed(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled = true
	cases := []struct {
		name, path, addr string
		port             uint16
	}{
		{"claude v1", `C:\Program Files\WindowsApps\Claude_1.0.100.0_x64__pzs8sxrjxfjjc\app\claude.exe`, "160.79.104.10", 443},
		{"claude v2 other folder", `C:\Program Files\WindowsApps\Claude_1.4.0.0_x64__pzs8sxrjxfjjc\app\claude.exe`, "160.79.104.10", 443},
		{"chatgpt", `C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2025.1.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe`, "104.18.39.21", 443},
		{"chatgpt next version", `C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2026.9.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe`, "104.18.39.21", 443},
		{"telegram tcp 443", `C:\Users\u\AppData\Roaming\Telegram Desktop\Telegram.exe`, "149.154.167.51", 443},
		{"telegram tcp 80", `C:\Users\u\AppData\Roaming\Telegram Desktop\Telegram.exe`, "149.154.175.50", 80},
		{"telegram tcp 5222", `D:\Apps\Telegram Desktop\Telegram.exe`, "91.108.56.130", 5222},
	}
	for i, tc := range cases {
		id := wp.ProcessIdentity{PID: uint32(100 + i), CreationTime: uint64(10 + i), Path: tc.path}
		d := c.Classify(id, destTuple("tcp", tc.addr, tc.port))
		if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure || d.Block || d.Route.Direct() {
			t.Fatalf("%s: not relay-first fail-closed: %+v", tc.name, d)
		}
		if _, err := c.Engine.OpenTCP(context.Background(), d.Flow); err == nil {
			t.Fatalf("%s: leaked to DIRECT while the relay is unavailable", tc.name)
		}
	}
	other := wp.ProcessIdentity{PID: 900, CreationTime: 90, Path: `C:\Tools\notes.exe`}
	if d := c.Classify(other, destTuple("tcp", "160.79.104.10", 443)); !d.Route.Direct() || !d.Deferred || !d.BlockOnFailure {
		t.Fatalf("unregistered application must await its own origin, not inherit another service relay: %+v", d)
	}
}

// Existing installs may already have a manual profile for the same program; the
// built-in one must not shadow it (two profiles for one exe would be ambiguous).
func TestPersistedProfileSuppressesShadowedBuiltIn(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	manual := profiles.Profile{ID: "my-telegram", Name: "Telegram", Executables: []string{`C:\Apps\Telegram\Telegram.exe`}, Mode: profiles.Auto, Custom: true}
	dropShadowedBuiltIns(c.Profiles, []profiles.Profile{manual})
	for _, p := range c.Profiles.List() {
		if p.ID == "telegram" {
			t.Fatal("built-in Telegram profile still registered next to the user's own")
		}
	}
	found := map[string]bool{}
	for _, p := range c.Profiles.List() {
		found[p.ID] = true
	}
	for _, id := range []string{"cs2", "discord", "steam", "claude-desktop", "chatgpt-desktop"} {
		if !found[id] {
			t.Fatalf("unrelated built-in %q was removed", id)
		}
	}
}

// Name resolution and local-network traffic must never be sent to the relay, whatever the
// profile's fail-closed setting: the relay refuses such destinations (relay_destination_denied)
// and a fail-closed profile would turn that refusal into a blocked flow and a dead app.
func TestRelayFirstProfilesKeepDNSAndLocalNetworkDirect(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled = true
	apps := map[string]string{
		"claude":   `C:\Program Files\WindowsApps\Claude_1.0.100.0_x64__pzs8sxrjxfjjc\app\claude.exe`,
		"chatgpt":  `C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2025.1.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe`,
		"telegram": `C:\Users\u\AppData\Roaming\Telegram Desktop\Telegram.exe`,
	}
	type flow struct {
		proto, addr string
		port        uint16
	}
	local := []flow{
		{"udp", "192.168.88.1", 53}, {"tcp", "192.168.88.1", 53}, // the router's resolver (observed failure)
		{"udp", "8.8.8.8", 53}, {"tcp", "1.1.1.1", 53}, // any resolver on port 53
		{"tcp", "192.168.88.20", 445}, {"tcp", "10.1.2.3", 443}, {"udp", "172.16.0.5", 5353}, {"tcp", "127.0.0.1", 8080},
		{"udp", "169.254.1.1", 1900}, {"udp", "224.0.0.251", 5353}, {"udp", "255.255.255.255", 67}, {"tcp", "100.64.0.9", 443},
	}
	for name, exe := range apps {
		for i, fl := range local {
			id := wp.ProcessIdentity{PID: uint32(500 + i), CreationTime: uint64(50 + i), Path: exe}
			d := c.Classify(id, destTuple(fl.proto, fl.addr, fl.port))
			if !d.Route.Direct() || d.Block || d.BlockOnFailure || d.ProbeDirect {
				t.Fatalf("%s %s %s:%d must stay DIRECT and unblocked: %+v", name, fl.proto, fl.addr, fl.port, d)
			}
			if d.Flow.PID != id.PID || d.Flow.ApplicationID == "" || d.Flow.PinnedPolicy == nil {
				t.Fatalf("%s: attribution lost or flow not pinned DIRECT: %+v", name, d.Flow)
			}
		}
		// Public traffic of the same application is still relay-first and fail-closed, TCP and QUIC alike.
		for _, fl := range []flow{{"tcp", "160.79.104.10", 443}, {"udp", "160.79.104.10", 443}, {"tcp", "149.154.167.51", 80}} {
			id := wp.ProcessIdentity{PID: 800, CreationTime: 80, Path: exe}
			d := c.Classify(id, destTuple(fl.proto, fl.addr, fl.port))
			if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure || d.Block {
				t.Fatalf("%s %s %s:%d lost relay-first/fail-closed: %+v", name, fl.proto, fl.addr, fl.port, d)
			}
		}
	}
}

// Codex helpers inherit the ChatGPT group; their DNS and LAN traffic is DIRECT too.
func TestChatGPTHelperProcessKeepsDNSDirect(t *testing.T) {
	p := profiles.Profile{ID: "openai", Name: "ChatGPT", Mode: profiles.Auto, Custom: true, Executables: []string{`C:\Apps\ChatGPT.exe`}}
	prepareAuto(&p)
	c := policyController(t, p)
	root := wp.ProcessIdentity{PID: 1, CreationTime: 10, Path: p.Executables[0]}
	child := wp.ProcessIdentity{PID: 2, CreationTime: 20, ParentPID: 1, ParentCreationTime: 10, Path: `C:\Apps\codex-version-dynamic\codex.exe`}
	c.discovery = &groupDiscovery{[]wp.ProcessIdentity{root, child}}
	if d := c.Classify(child, destTuple("udp", "192.168.88.1", 53)); !d.Route.Direct() || d.BlockOnFailure || d.Block {
		t.Fatalf("helper DNS leaked into the relay path: %+v", d)
	}
	if d := c.Classify(child, destTuple("tcp", "160.79.104.10", 443)); d.Route.RelayID != "VPS-01" || !d.BlockOnFailure {
		t.Fatalf("helper lost fail-closed relay-first: %+v", d)
	}
}
