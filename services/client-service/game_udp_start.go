package clientservice

import (
	"net/netip"
	"os"
	"path"
	"path/filepath"

	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
)

func (c *Controller) newGameLadder(profileID, executable string) *gameudp.Engine {
	e := gameudp.NewLadder(c.games.budget)
	e.SetEndpointScoped()
	if profileID == "cs2" && path.Base(gameudp.Canonical(executable)) == "cs2.exe" {
		e.SetCS2STUNEndpoint(c.games.cs2STUNEndpoint)
	}
	return e
}

// Keep the optional CS2 endpoint separate from the existing game profile
// format so a previous service build can still read the user's game settings.
func (c *Controller) loadCS2STUNEndpoint() {
	if c.customPath == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(c.customPath), "game-udp-cs2.json"))
	if os.IsNotExist(err) {
		return
	}
	var config struct {
		Endpoint string `json:"endpoint"`
	}
	if err != nil || len(raw) > 1024 || security.Parse(raw, &config) != nil {
		c.games.cs2STUNInvalid = true
		return
	}
	endpoint, err := netip.ParseAddrPort(config.Endpoint)
	if err != nil || endpoint.String() != config.Endpoint || !endpoint.Addr().Is4() ||
		endpoint.Port() < 1024 || routing.LocalDestination(endpoint.Addr()) {
		c.games.cs2STUNInvalid = true
		return
	}
	c.games.cs2STUNEndpoint = endpoint
}
