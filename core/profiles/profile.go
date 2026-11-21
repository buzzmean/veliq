package profiles

import (
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Mode string

const (
	Auto       Mode = "AUTO"
	Direct     Mode = "DIRECT"
	DirectPlus Mode = "DIRECT_PLUS"
	Manual     Mode = "MANUAL"
	Block      Mode = "BLOCK"
)

type TrialScope struct {
	PID          uint32    `json:"pid"`
	CreationTime uint64    `json:"creation_time"`
	Expires      time.Time `json:"expires"`
}
type Profile struct {
	BrowserAutoDisabled bool   `json:"browser_auto_disabled,omitempty"`
	BrowserTransport    string `json:"browser_transport,omitempty"`
	// Recovery preserves domain rules while a fail-closed Chrome PAC guards them.
	BrowserRecoveryRules []flowpolicy.Rule    `json:"browser_recovery_rules,omitempty"`
	Trial                *TrialScope          `json:"trial_scope,omitempty"`
	AutoRevision         string               `json:"auto_revision,omitempty"`
	AutoNetwork          string               `json:"auto_network,omitempty"`
	Rules                []flowpolicy.Rule    `json:"rules,omitempty"`
	Fallback             flowpolicy.Fallback  `json:"fallback,omitempty"`
	AppPreset            string               `json:"app_preset,omitempty"`
	Identity             *ApplicationIdentity `json:"identity,omitempty"`
	LocalStrategyID      string               `json:"local_strategy_id,omitempty"`
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	Executables          []string             `json:"executables"`
	Publisher            string               `json:"publisher,omitempty"`
	SignatureSHA256      string               `json:"signature_sha256,omitempty"`
	ProtocolHints        []string             `json:"protocol_hints,omitempty"`
	PortHints            []uint16             `json:"port_hints,omitempty"`
	Mode                 Mode                 `json:"mode"`
	RelayID              string               `json:"relay_id,omitempty"`
	Custom               bool                 `json:"custom"`
}

func (p Profile) Validate() error {
	if p.BrowserTransport != "" && p.BrowserTransport != "native" {
		return errors.New("invalid browser transport")
	}
	if p.Trial != nil && (p.Trial.PID == 0 || p.Trial.CreationTime == 0 || !strings.HasPrefix(p.ID, "!v2-") || !p.Custom) {
		return errors.New("invalid trial scope")
	}
	if len(p.AppPreset) > 64 {
		return errors.New("invalid application preset")
	}
	if len(p.AutoRevision) > 128 {
		return errors.New("invalid auto revision")
	}
	if len(p.AutoNetwork) > 128 {
		return errors.New("invalid auto network binding")
	}
	if len(p.Rules) > 24 || len(p.BrowserRecoveryRules) > 24 {
		return errors.New("too many flow rules")
	}
	for _, r := range append(append([]flowpolicy.Rule{}, p.Rules...), p.BrowserRecoveryRules...) {
		if err := r.Validate(); err != nil {
			return err
		}
	}
	switch p.Fallback {
	case "", flowpolicy.FailOpen, flowpolicy.Required, flowpolicy.FailBlock:
	default:
		return errors.New("invalid profile fallback")
	}
	if p.Identity != nil {
		if err := p.Identity.Validate(); err != nil {
			return err
		}
	}
	if len(p.LocalStrategyID) > 64 {
		return errors.New("invalid local strategy id")
	}
	if len(p.ID) < 1 || len(p.ID) > 128 || p.Name == "" || len(p.Name) > 128 || len(p.Executables) < 1 || len(p.Executables) > 16 {
		return errors.New("invalid application profile")
	}
	for _, exe := range p.Executables {
		if len(exe) > 2048 || !strings.HasSuffix(strings.ToLower(exe), ".exe") {
			return errors.New("profile requires .exe identity")
		}
	}
	switch p.Mode {
	case Auto, Direct, DirectPlus, Block:
	case Manual:
		if p.RelayID == "" {
			return errors.New("manual mode requires relay")
		}
	default:
		return errors.New("invalid routing mode")
	}
	return nil
}

// BuiltInRelayFirstIDs are the default profiles for services that are blocked for
// the user. They match by executable name, not by path: packaged apps live in
// versioned WindowsApps folders that change with every update.
var BuiltInRelayFirstIDs = []string{"claude-desktop", "chatgpt-desktop", "telegram"}

func Defaults() []Profile {
	return []Profile{
		{ID: "riot-client", Name: "Riot Client (launcher)", Executables: RiotLauncherExecutables(), Mode: Auto, AppPreset: "riot-client", ProtocolHints: []string{"tcp"}, PortHints: []uint16{443}},
		{ID: "cs2", Name: "Counter-Strike 2", Executables: []string{"cs2.exe"}, Mode: Direct, ProtocolHints: []string{"udp", "tcp"}},
		{ID: "discord", Name: "Discord", Executables: []string{"Discord.exe"}, Mode: Auto},
		{ID: "steam", Name: "Steam", Executables: []string{"steam.exe"}, Mode: Direct},
		{ID: "claude-desktop", Name: "Claude (desktop)", Executables: []string{"claude.exe"}, Mode: Auto, AppPreset: "anthropic", Fallback: flowpolicy.Required},
		// Codex helpers are covered only through verified ancestry from ChatGPT.exe
		// (Identity.Helpers); a stray codex.exe must never inherit the protected group.
		{ID: "chatgpt-desktop", Name: "ChatGPT / Codex (desktop)", Executables: []string{"ChatGPT.exe"}, Mode: Auto, AppPreset: "openai", Fallback: flowpolicy.Required,
			Identity: &ApplicationIdentity{Root: "c:/program files/windowsapps", Executable: "ChatGPT.exe", Helpers: []string{"codex.exe", "codex-windows-sandbox-service.exe", "codex-computer-use-swift.exe"}}},
		{ID: "telegram", Name: "Telegram Desktop", Executables: []string{"Telegram.exe"}, Mode: Auto, AppPreset: "telegram", Fallback: flowpolicy.Required},
	}
}

type Identity struct {
	PID                                    uint32
	Path, Name, Publisher, SignatureSHA256 string
	CreationTime                           uint64
	ParentPID                              uint32
	ParentCreationTime                     uint64
}

func normalize(s string) string { return strings.ToLower(strings.ReplaceAll(s, "\\", "/")) }
func (p Profile) Matches(i Identity) bool {
	if p.ID == "riot-client" && !RiotLauncherPath(i.Path) {
		return false
	}
	if p.Trial != nil && (i.PID != p.Trial.PID || i.CreationTime != p.Trial.CreationTime || !time.Now().Before(p.Trial.Expires)) {
		return false
	}
	if i.PID == 0 || i.Path == "" || i.CreationTime == 0 {
		return false
	}
	if p.Publisher != "" && p.Publisher != i.Publisher {
		return false
	}
	if p.SignatureSHA256 != "" && !strings.EqualFold(p.SignatureSHA256, i.SignatureSHA256) {
		return false
	}
	if p.Identity != nil && p.Identity.Matches(i) {
		return true
	}
	path := normalize(i.Path)
	for _, exe := range p.Executables {
		v := normalize(exe)
		if strings.Contains(v, "/") {
			if v == path {
				return true
			}
		} else if v == filepath.Base(path) {
			return true
		}
	}
	return false
}

type Registry struct {
	mu    sync.RWMutex
	items map[string]Profile
}

func New(all []Profile) *Registry {
	r := &Registry{items: make(map[string]Profile)}
	for _, p := range all {
		r.Upsert(p)
	}
	return r
}
func (r *Registry) Upsert(p Profile) error {
	if e := p.Validate(); e != nil {
		return e
	}
	p = clone(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[p.ID]; !ok && len(r.items) >= 128 {
		return errors.New("profile capacity reached")
	}
	total := 0
	for id, old := range r.items {
		if id != p.ID {
			b, _ := json.Marshal(old)
			total += len(b)
		}
	}
	b, _ := json.Marshal(p)
	if total+len(b) > 24000 {
		return errors.New("profile storage limit reached")
	}
	r.items[p.ID] = p
	return nil
}
func (r *Registry) List() []Profile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Profile, 0, len(r.items))
	for _, p := range r.items {
		p = clone(p)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (r *Registry) Match(i Identity) (Profile, bool) {
	all := r.List()
	sort.SliceStable(all, func(a, b int) bool { return all[a].Custom && !all[b].Custom })
	for _, p := range all {
		if p.Matches(i) {
			return p, true
		}
	}
	return Profile{}, false
}

func (r *Registry) Delete(id string) { r.mu.Lock(); defer r.mu.Unlock(); delete(r.items, id) }

func clone(p Profile) Profile {
	if p.Trial != nil {
		v := *p.Trial
		p.Trial = &v
	}
	p.Executables = append([]string(nil), p.Executables...)
	p.Rules = append([]flowpolicy.Rule(nil), p.Rules...)
	p.BrowserRecoveryRules = append([]flowpolicy.Rule(nil), p.BrowserRecoveryRules...)
	for _, rules := range [][]flowpolicy.Rule{p.Rules, p.BrowserRecoveryRules} {
		for i := range rules {
			rules[i].Domains = append([]string(nil), rules[i].Domains...)
			rules[i].CIDRs = append([]string(nil), rules[i].CIDRs...)
			rules[i].Ports = append([]flowpolicy.PortRange(nil), rules[i].Ports...)
		}
	}
	if p.Identity != nil {
		v := *p.Identity
		v.Helpers = append([]string(nil), v.Helpers...)
		p.Identity = &v
	}
	return p
}
