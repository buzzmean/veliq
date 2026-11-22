package clientservice

import (
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
)

func (c *Controller) newGameLadder(profileID, executable string) *gameudp.Engine {
	e := gameudp.NewLadder(c.games.budget)
	e.SetEndpointScoped()
	exe := path.Base(gameudp.Canonical(executable))
	if profileID == "cs2" && exe == "cs2.exe" {
		e.SetCS2STUNScope(c.games.cs2STUNEndpoint, c.games.cs2STUNPorts)
	}
	if profileID == "apex" && (exe == "r5apex_dx12.exe" || exe == "r5apex.exe") {
		e.PreferLocalWithoutRelay()
	}
	return e
}

// Keep the optional CS2 scope separate from the existing game profile
// format so a previous service build can still read the user's game settings.
func (c *Controller) loadCS2STUNScope() {
	if c.customPath == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(c.customPath), "game-udp-cs2.json"))
	if os.IsNotExist(err) {
		return
	}
	var config struct {
		Endpoint string   `json:"endpoint"`
		Ports    []uint16 `json:"ports"`
	}
	if err != nil || len(raw) > 1024 || security.Parse(raw, &config) != nil {
		c.games.cs2STUNInvalid = true
		return
	}
	if config.Endpoint == "" && len(config.Ports) > 0 {
		for _, port := range config.Ports {
			if port < 1024 {
				c.games.cs2STUNInvalid = true
				return
			}
		}
		slices.Sort(config.Ports)
		c.games.cs2STUNPorts = slices.Compact(config.Ports)
		return
	}
	endpoint, err := netip.ParseAddrPort(config.Endpoint)
	if len(config.Ports) > 0 || err != nil || endpoint.String() != config.Endpoint || !endpoint.Addr().Is4() ||
		endpoint.Port() < 1024 || routing.LocalDestination(endpoint.Addr()) {
		c.games.cs2STUNInvalid = true
		return
	}
	c.games.cs2STUNEndpoint = endpoint
}
