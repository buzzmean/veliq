package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func policyController(t *testing.T, p profiles.Profile) *Controller {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled = true
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	return c
}
func policyTuple(proto string, port uint16) wp.Tuple {
	return wp.Tuple{Protocol: proto, Source: netip.MustParseAddrPort("192.0.2.1:55000"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), port)}
}
func TestDiscordHybridAndRequiredIsolation(t *testing.T) {
	p := profiles.Profile{ID: "custom-discord", Name: "Discord", Executables: []string{`C:\Apps\Discord\app-1.0.9212\Discord.exe`}, Mode: profiles.Auto, Custom: true}
	prepareAuto(&p)
	c := policyController(t, p)
	id := wp.ProcessIdentity{PID: 1, CreationTime: 10, Path: `C:\Apps\Discord\app-1.0.9262\Discord.exe`}
	tcp := c.Classify(id, policyTuple("tcp", 443))
	udp := c.Classify(id, policyTuple("udp", 19323))
	quic := c.Classify(id, policyTuple("udp", 443))
	if tcp.Route.RelayID != "VPS-01" || !tcp.BlockOnFailure || tcp.Flow.PinnedPolicy == nil {
		t.Fatal(tcp)
	}
	if !udp.Route.Direct() || !udp.ProbeDirect || udp.Policy.Fallback != flowpolicy.FlowRelay {
		t.Fatal(udp)
	}
	if udp.Flow.UDPFakePrelude != 6 || udp.Flow.UDPFakeCutoff != 2 || tcp.Flow.UDPFakePrelude != 0 || quic.Flow.UDPFakePrelude != 0 {
		t.Fatal("Discord voice fake prelude scope", udp.Flow, tcp.Flow, quic.Flow)
	}
	if quic.ProbeDirect || !quic.BlockOnFailure || quic.Route.RelayID != "VPS-01" {
		t.Fatal("QUIC treated as voice", quic)
	}
	if dns := c.Classify(id, policyTuple("udp", 53)); dns.ProbeDirect {
		t.Fatal("DNS treated as media", dns)
	}
	if _, err := c.Engine.OpenTCP(context.Background(), tcp.Flow); err == nil {
		t.Fatal("required leaked through global DIRECT")
	}
	other := id
	other.Path = `C:\Other\Other.exe`
	if d := c.Classify(other, policyTuple("tcp", 443)); !d.Route.Direct() || d.Block || d.Group == p.ID || !d.Deferred {
		t.Fatal("unrelated application inherited Discord instead of its own origin policy", d)
	}
}
func TestDomainDecisionPinnedAcrossProfileChanges(t *testing.T) {
	p := profiles.Profile{ID: "browser", Name: "Browser", Executables: []string{`C:\Apps\browser.exe`}, Mode: profiles.Auto, Custom: true, Fallback: flowpolicy.FailBlock, Rules: []flowpolicy.Rule{{ID: "auth", Protocol: "tcp", Domains: []string{"auth.example"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}, {ID: "video", Protocol: "tcp", Domains: []string{"video.example"}, Action: flowpolicy.DirectPlus, Strategy: "disorder"}}}
	c := policyController(t, p)
	id := wp.ProcessIdentity{PID: 1, CreationTime: 10, Path: p.Executables[0]}
	syn := c.Classify(id, policyTuple("tcp", 443))
	if !syn.Deferred || syn.ResolveDomain == nil {
		t.Fatal("SNI decided at SYN")
	}
	a := syn.ResolveDomain("auth.example")
	b := syn.ResolveDomain("video.example")
	if a.Route.RelayID != "VPS-01" || !a.BlockOnFailure || !b.Route.Local() {
		t.Fatal(a, b)
	}
	p.Mode = profiles.Direct
	p.Rules = nil
	c.Profiles.Upsert(p)
	if d := syn.ResolveDomain("auth.example"); d.Route.RelayID != "VPS-01" {
		t.Fatal("live flow reclassified")
	}
	if d := c.Classify(id, policyTuple("tcp", 443)); !d.Route.Direct() || d.Deferred {
		t.Fatal("new connection not updated", d)
	}
}

type groupDiscovery struct{ all []wp.ProcessIdentity }

func (g *groupDiscovery) List() ([]wp.ProcessIdentity, error) { return g.all, nil }
func (g *groupDiscovery) Lookup(pid uint32) (wp.ProcessIdentity, error) {
	for _, id := range g.all {
		if id.PID == pid {
			return id, nil
		}
	}
	return wp.ProcessIdentity{}, wp.ErrUnavailable
}
func TestChatGPTHelpersAncestryAndRootExit(t *testing.T) {
	p := profiles.Profile{ID: "openai", Name: "ChatGPT", Mode: profiles.Auto, Custom: true, Executables: []string{`C:\Apps\ChatGPT.exe`}}
	prepareAuto(&p)
	c := policyController(t, p)
	root := wp.ProcessIdentity{PID: 1, CreationTime: 10, Path: p.Executables[0]}
	child := wp.ProcessIdentity{PID: 2, CreationTime: 20, ParentPID: 1, ParentCreationTime: 10, Path: `C:\Apps\codex-version-dynamic\codex.exe`}
	g := &groupDiscovery{[]wp.ProcessIdentity{root, child}}
	c.discovery = g
	d := c.Classify(child, policyTuple("tcp", 443))
	if !d.BlockOnFailure || d.Route.RelayID != "VPS-01" || d.Group != "openai" {
		t.Fatal(d)
	}
	g.all = []wp.ProcessIdentity{child}
	c.groupAt = time.Time{}
	if d = c.Classify(child, policyTuple("tcp", 443)); !d.BlockOnFailure {
		t.Fatal("already attributed helper lost group after root exit")
	}
	other := child
	other.CreationTime = 30
	other.Path = `C:\Other\codex.exe`
	other.ParentPID = 0
	other.ParentCreationTime = 0
	g.all = []wp.ProcessIdentity{other}
	c.groupAt = time.Time{}
	if d = c.Classify(other, policyTuple("tcp", 443)); !d.Route.Direct() || d.Group == "openai" || !d.Deferred {
		t.Fatal("reused PID borrowed protected group")
	}
}
func TestPresetIsolationPreservesChromeAndPendingGeneration(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	chrome := `C:\Apps\chrome.exe`
	discord := `C:\Apps\Discord.exe`
	apply := func(app, preset string) {
		b, _ := json.Marshal(map[string]any{"application": app, "preset": preset, "quic_fallback": true})
		if _, err := c.handleLocal("local.preset.apply", b); err != nil {
			t.Fatal(err)
		}
	}
	apply(chrome, "youtube")
	before := c.Local.Config().User
	apply(discord, "discord")
	after := c.Local.Config().User
	count := 0
	for _, p := range before {
		for _, q := range after {
			if p.ID == q.ID {
				a, _ := json.Marshal(p)
				b, _ := json.Marshal(q)
				if string(a) != string(b) {
					t.Fatal("Chrome strategy mutated")
				}
				count++
			}
		}
	}
	if count != len(before) {
		t.Fatal("Chrome strategy deleted")
	}
	if len(c.Profiles.List()) != len(profiles.Defaults()) {
		t.Fatal("preset mutated routing profiles")
	}
}
func TestTrialRootCannotAffectOrdinaryBrowserOrOldRoot(t *testing.T) {
	path := `C:\Apps\chrome.exe`
	normal := profiles.Profile{ID: "normal", Name: "Chrome", Executables: []string{path}, Mode: profiles.Direct, Custom: true}
	c := policyController(t, normal)
	root := wp.ProcessIdentity{PID: 100, CreationTime: 10, Path: path}
	child := wp.ProcessIdentity{PID: 101, CreationTime: 20, ParentPID: 100, ParentCreationTime: 10, Path: path}
	ordinary := wp.ProcessIdentity{PID: 200, CreationTime: 10, Path: path}
	c.discovery = &groupDiscovery{[]wp.ProcessIdentity{root, child, ordinary}}
	temp := profiles.Profile{ID: "!v2-test", Name: "Isolated", Executables: []string{path}, Mode: profiles.Manual, RelayID: "VPS-01", Custom: true, Trial: &profiles.TrialScope{PID: 100, CreationTime: 10, Expires: time.Now().Add(time.Minute)}}
	raw, _ := json.Marshal(temp)
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(child, policyTuple("tcp", 443)); d.Route.RelayID != "VPS-01" {
		t.Fatal("trial child not scoped", d)
	}
	if d := c.Classify(ordinary, policyTuple("tcp", 443)); !d.Route.Direct() {
		t.Fatal("ordinary browser captured by tester", d)
	}
	temp.Trial.PID = 200
	raw, _ = json.Marshal(temp)
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(child, policyTuple("tcp", 443)); !d.Route.Direct() {
		t.Fatal("old trial binding borrowed new root", d)
	}
}
func TestAutoPlanCooldownAndNoInventedCommit(t *testing.T) {
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto, Custom: true}
	c := policyController(t, p)
	c.network.Store(&wp.NetworkContext{Fingerprint: "ISP", ObservedAt: time.Now()})
	raw, _ := json.Marshal(map[string]string{"profile_id": p.ID})
	plan, err := c.handleAuto("auto.plan", raw)
	if err != nil {
		t.Fatal(err)
	}
	m := plan.(map[string]any)
	if !m["needs_trial"].(bool) || len(m["candidates"].([]string)) != 7 {
		t.Fatal(m)
	}
	if _, err = c.handleAuto("auto.plan", raw); err == nil {
		t.Fatal("unbounded repeated probes")
	}
	commit, _ := json.Marshal(map[string]string{"profile_id": p.ID, "lease": m["lease"].(string)})
	if _, err = c.handleAuto("auto.commit", commit); err == nil {
		t.Fatal("winner invented without proof")
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "other-ISP", ObservedAt: time.Now()})
	if _, err = c.handleAuto("auto.commit", commit); err == nil {
		t.Fatal("old network commit accepted")
	}
}
func TestWorkingBaselineSurvivesDiscordButNotOwnStrategyEdit(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	app := `C:\Apps\chrome.exe`
	entries, _, _ := localstrategy.PresetProfiles("youtube", app, true)
	selected := ""
	for _, p := range entries {
		if strings.HasSuffix(p.ID, "-disorder") {
			selected = p.ID
		}
	}
	if selected == "" {
		t.Fatal("missing existing disorder")
	}
	c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: entries})
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{app}, Mode: profiles.Auto, LocalStrategyID: selected, AutoNetwork: "ISP"}
	p.AutoRevision = c.baselineRevision(p)
	if !c.hasBaseline(p, "ISP") {
		t.Fatal("baseline not bound")
	}
	discord, _, _ := localstrategy.PresetProfiles("discord", `C:\Apps\Discord.exe`, true)
	c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: append(entries, discord...)})
	if !c.hasBaseline(p, "ISP") {
		t.Fatal("Discord invalidated YouTube")
	}
	for i := range entries {
		if entries[i].ID == selected {
			entries[i].Name = "edited candidate"
		}
	}
	c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: entries})
	if c.hasBaseline(p, "ISP") || c.hasBaseline(p, "new-ISP") {
		t.Fatal("changed candidate/network reused old baseline")
	}
}
func TestOldClientUpdatePreservesPerProfileSafety(t *testing.T) {
	p := profiles.Profile{ID: "protected", Name: "OpenAI", Executables: []string{`C:\Apps\ChatGPT.exe`}, Mode: profiles.Auto, Custom: true}
	prepareAuto(&p)
	c := policyController(t, p)
	raw, _ := json.Marshal(map[string]any{"id": p.ID, "name": "Renamed", "executables": p.Executables, "mode": "MANUAL", "relay_id": "VPS-01", "custom": true})
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Profiles.List() {
		if v.ID == p.ID {
			if v.Fallback != flowpolicy.Required || v.Identity == nil {
				t.Fatal("old client erased safety", v)
			}
		}
	}
}
func TestNetworkChangeBeforeLateDecisionClosesOnlyPendingFlow(t *testing.T) {
	p := profiles.Profile{ID: "browser", Name: "Browser", Executables: []string{`C:\Apps\browser.exe`}, Mode: profiles.Auto, Custom: true, Rules: []flowpolicy.Rule{{ID: "auth", Protocol: "tcp", Domains: []string{"auth.example"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}}
	c := policyController(t, p)
	c.network.Store(&wp.NetworkContext{Fingerprint: "ISP-a", ObservedAt: time.Now()})
	d := c.Classify(wp.ProcessIdentity{PID: 1, CreationTime: 1, Path: p.Executables[0]}, policyTuple("tcp", 443))
	c.network.Store(&wp.NetworkContext{Fingerprint: "ISP-b", ObservedAt: time.Now()})
	resolved := d.ResolveDomain("auth.example")
	if !resolved.Block || resolved.Policy.Source != "network_changed" {
		t.Fatal("old network rule used", resolved)
	}
}
func TestIPv6CannotBypassDeferredDomainRule(t *testing.T) {
	p := profiles.Profile{ID: "browser", Name: "Browser", Executables: []string{`C:\Apps\browser.exe`}, Mode: profiles.Auto, Custom: true, Rules: []flowpolicy.Rule{{ID: "auth", Protocol: "tcp", Domains: []string{"auth.example"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}}
	c := policyController(t, p)
	tuple := wp.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("[2001:db8::1]:1200"), Destination: netip.MustParseAddrPort("[2001:db8::2]:443")}
	d := c.Classify(wp.ProcessIdentity{PID: 1, CreationTime: 1, Path: p.Executables[0]}, tuple)
	if !d.Block || d.Deferred || d.Policy.Source != "unsupported_ipv6_domain_policy" {
		t.Fatal("unsupported domain-aware IPv6 leaked", d)
	}
}
func TestPerProfileRequiredFallbackAlsoReachesTransportPolicy(t *testing.T) {
	p := profiles.Profile{ID: "manual-required", Name: "Sensitive", Executables: []string{`C:\Apps\sensitive.exe`}, Mode: profiles.Manual, RelayID: "offline", Fallback: flowpolicy.Required, Custom: true}
	c := policyController(t, p)
	c.syncPolicies()
	f := routing.Flow{PID: 1, ProcessPath: p.Executables[0], ApplicationID: p.ID, Source: policyTuple("tcp", 443).Source, Destination: policyTuple("tcp", 443).Destination}
	if _, err := c.Engine.OpenTCP(context.Background(), f); err == nil {
		t.Fatal("raw transport bypassed per-profile fallback")
	}
}

func TestChromeAutoThreeOriginsNeverUsesGlobalWinner(t *testing.T) {
	app := `C:\Apps\chrome.exe`
	p := profiles.Profile{ID: "browser", Name: "Chrome", Executables: []string{app}, Mode: profiles.Auto, Custom: true, AppPreset: "openai-web", RelayID: "VPS-01"}
	c := policyController(t, p)
	c.network.Store(&wp.NetworkContext{Fingerprint: "ISP", ObservedAt: time.Now()})
	local, _, err := localstrategy.PresetProfiles("youtube", app, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range local {
		if strings.HasSuffix(v.ID, "-disorder") {
			p.LocalStrategyID = v.ID
		}
	}
	if err = c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: local}); err != nil {
		t.Fatal(err)
	}
	p.AutoNetwork = "ISP"
	p.AutoRevision = c.baselineRevision(p)
	if err = c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	id := wp.ProcessIdentity{PID: 100, CreationTime: 10, Path: app}
	tuple := policyTuple("tcp", 443)
	for domain, want := range map[string]flowpolicy.Action{"chatgpt.com": flowpolicy.RelayRequired, "api.openai.com": flowpolicy.RelayRequired, "www.youtube.com": flowpolicy.DirectPlus, "r1.googlevideo.com": flowpolicy.DirectPlus, "www.example.org": flowpolicy.Direct, "openai.com.evil.test": flowpolicy.Direct} {
		before := c.Classify(id, tuple)
		if !before.Deferred || before.ResolveDomain == nil {
			t.Fatal("upstream selected before domain", domain, before)
		}
		d := wp.ResolveDeferredDecision(before, domain, "SNI_FOUND")
		if d.Policy.Action != want || d.Flow.PinnedPolicy == nil || d.Flow.PinnedPolicy.Route != d.Route {
			t.Fatal(domain, d)
		}
		if want == flowpolicy.RelayRequired && (!d.BlockOnFailure || d.Route.RelayID != "VPS-01") {
			t.Fatal("protected downgrade", d)
		}
		if want == flowpolicy.Direct && (!d.Route.Direct() || d.Local != nil) {
			t.Fatal("global baseline leaked", d)
		}
	}
	opaque := wp.ResolveDeferredDecision(c.Classify(id, tuple), "cloudflare-ech.com", "ECH_OUTER_SNI_ONLY")
	if opaque.Block || !opaque.BlockOnFailure || opaque.Route.RelayID != "VPS-01" || opaque.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal("opaque inner name guessed DIRECT", opaque)
	}
	old := wp.ResolveDeferredDecision(c.Classify(id, tuple), "chatgpt.com", "SNI_FOUND")
	p.Mode = profiles.Direct
	c.Profiles.Upsert(p)
	if !old.BlockOnFailure || old.Route.RelayID != "VPS-01" {
		t.Fatal("existing decision mutated")
	}
}

func TestBrowserCandidateIsScopedAndPreservesConfiguredBaseline(t *testing.T) {
	app := `C:\Apps\chrome.exe`
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Mode: profiles.Auto, Executables: []string{app}, LocalStrategyID: "local"}
	c := policyController(t, p)
	c.network.Store(&wp.NetworkContext{Fingerprint: "isp", ObservedAt: time.Now()})
	cfg := localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "local", Name: "baseline", Version: 1, Application: app, Enabled: true, Protocol: "tcp", Ports: []uint16{443}, Domains: []string{"youtube.com"}, IPs: []string{"203.0.113.1"}, Strategy: "tcp-split-1", Cutoff: 1}}}
	if e := c.Local.Reload(cfg); e != nil {
		t.Fatal(e)
	}
	p.AutoNetwork = "isp"
	p.AutoRevision = c.baselineRevision(p)
	id, engine := c.browserScopedLocal(p, "unknown.example", "isp", 8443)
	if id == "" || engine == nil {
		t.Fatal("missing real candidate")
	}
	candidate := engine.Config().User[0]
	if len(candidate.Domains) != 1 || candidate.Domains[0] != "unknown.example" || len(candidate.IPs) != 0 || len(candidate.Ports) != 1 || candidate.Ports[0] != 8443 {
		t.Fatal(candidate)
	}
	other, _ := c.browserScopedLocal(p, "unknown.example", "isp", 443)
	if other == id {
		t.Fatal("candidate crossed origin port")
	}
	if c.Local.Config().User[0].Domains[0] != "youtube.com" || c.Local.Config().User[0].Ports[0] != 443 {
		t.Fatal("modified user's baseline")
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "isp", ObservedAt: time.Now(), Conflicts: []string{"external capture"}})
	if id, _ := c.browserScopedLocal(p, "unknown.example", "isp", 8443); id != "" {
		t.Fatal("bypassed existing local strategy safety gate")
	}
}

func TestInactiveBrowserStatusHasEmptyArray(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	status, e := c.Handle(context.Background(), "browser.status", nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(status)
	if e != nil || !strings.Contains(string(raw), `"records":[]`) {
		t.Fatal(string(raw), e)
	}
}
