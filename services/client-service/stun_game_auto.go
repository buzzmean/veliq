package clientservice

import (
	"path"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func (c *Controller) classifySTUNGameAuto(id wp.ProcessIdentity, t wp.Tuple) (wp.Decision, bool) {
	if path.Base(gameudp.Canonical(id.Path)) == "cs2.exe" || !stunGameImage(id.Path) || id.PID == 0 || id.CreationTime == 0 {
		return wp.Decision{}, false
	}
	p, ok := c.matchApplication(id)
	if !ok || p.Mode != profiles.Auto || !gameProfileSafe(p) || len(p.Executables) != 1 || gameudp.Canonical(p.Executables[0]) != gameudp.Canonical(id.Path) {
		return wp.Decision{}, false
	}
	d := cs2DirectDecision(p, id, t)
	d.CS2Auto = false
	d.Revision, d.Policy.Source = "game-stun687-v1", "game_stun"
	if c.cs2RouteBlocked(p, t, "") {
		d.Block, d.BlockOnFailure = true, true
		d.Policy.Action, d.Policy.Fallback = flowpolicy.Block, flowpolicy.FailBlock
		return d, true
	}
	if gameudp.Eligible(id.Path, id.Path, t.Protocol, t.Destination) {
		if game, found := c.classifyGameUDP(id, t); found {
			return game, true
		}
	}
	return d, true
}
