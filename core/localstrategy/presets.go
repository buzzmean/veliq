package localstrategy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
)

const PresetVersion = 2

// Manually curated, scoped subsets reviewed against Flowseal eb16c141. See
// third_party/NOTICE.md and docs/DIRECT_PLUS_V2.md. No runtime list downloads.
type Preset struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Version    int         `json:"version"`
	Domains    []string    `json:"domains"`
	Ports      []uint16    `json:"ports"`
	Candidates []Candidate `json:"candidates"`
}
type Candidate struct {
	ID      string   `json:"id"`
	Actions []Action `json:"actions"`
}

func candidates() []Candidate {
	split := func(anchor string, positions ...uint16) Action {
		return Action{Kind: "tcp-multisplit", Anchor: anchor, Positions: positions}
	}
	fake := func(ttl uint8) Action { return Action{Kind: "fake-tls", TTL: ttl} }
	return []Candidate{
		{"split1", []Action{split("", 1)}},
		{"sni", []Action{split("sni", 1, 5)}},
		{"disorder", []Action{split("sni", 1, 5), {Kind: "tcp-disorder"}}},
		{"fake2", []Action{fake(2), split("sni", 1, 5)}},
		{"fake5", []Action{fake(5), split("sni", 1, 5)}},
		{"fake8-disorder", []Action{fake(8), split("sni", 1, 5), {Kind: "tcp-disorder"}}},
		{"fake5-only", []Action{fake(5)}},
	}
}
func Presets() []Preset {
	return []Preset{
		{"riot-client", "Riot Client (launcher)", PresetVersion, []string{"riotgames.com", "riotcdn.net", "pvp.net"}, []uint16{443}, candidates()},
		{"discord", "Discord", PresetVersion, []string{"discord.com", "discordapp.com", "discordapp.net", "discordcdn.com", "discord.gg", "discord.media", "discordstatus.com", "discord.gift", "discordactivities.com", "discord-activities.com", "discord-attachments-uploads-prd.storage.googleapis.com"}, []uint16{443, 2053, 2083, 2087, 2096, 8443}, candidates()},
		{"youtube", "YouTube", PresetVersion, []string{"youtube.com", "googlevideo.com", "ytimg.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com", "youtubeembeddedplayer.googleapis.com", "youtubekids.com", "youtu.be", "yt3.ggpht.com", "yt4.ggpht.com", "yt3.googleusercontent.com", "wide-youtube.l.google.com", "youtube-ui.l.google.com", "ytimg.l.google.com", "jnn-pa.googleapis.com"}, []uint16{443}, candidates()},
	}
}
func PresetProfiles(id, app string, quic bool) ([]Profile, string, error) {
	driveAbsolute := len(app) >= 3 && ((app[0] >= 'A' && app[0] <= 'Z') || (app[0] >= 'a' && app[0] <= 'z')) && app[1] == ':' && (app[2] == '\\' || app[2] == '/')
	if len(app) > 2048 || !strings.HasSuffix(strings.ToLower(app), ".exe") || !(filepath.IsAbs(app) || driveAbsolute) {
		return nil, "", errors.New("full executable path required")
	}
	hash := sha256.Sum256([]byte(strings.ToLower(strings.ReplaceAll(app, `\`, "/"))))
	for _, preset := range Presets() {
		if preset.ID == id {
			domains := []string{}
			for _, d := range preset.Domains {
				domains = append(domains, d, "*."+d)
			}
			out := []Profile{}
			selected := ""
			for _, candidate := range preset.Candidates {
				key := "p2-" + id + "-" + hex.EncodeToString(hash[:4]) + "-" + candidate.ID
				out = append(out, Profile{ID: key, Name: preset.Name + " v2 / " + candidate.ID, Version: Version, Protocol: "tcp", Ports: preset.Ports, Application: app, Domains: domains, Strategy: "chain", Actions: candidate.Actions, Preset: id, PresetVersion: PresetVersion, QuicFallback: quic, Cutoff: 1, Enabled: true})
				if candidate.ID == "fake5" {
					selected = key
				}
			}
			return out, selected, nil
		}
	}
	return nil, "", errors.New("unknown built-in preset")
}
func (e *LocalStrategyEngine) HasApplication(app string) bool {
	s := e.current.Load()
	if !s.config.Enabled {
		return false
	}
	for _, p := range s.profiles {
		if p.Enabled && appMatch(p.Application, app) {
			return true
		}
	}
	return false
}
