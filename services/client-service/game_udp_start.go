package clientservice

import (
	"github.com/buzzmean/neexitlag/core/gameudp"
	"path"
)

func (c *Controller) newGameLadder(executable string) *gameudp.Engine {
	e := gameudp.NewLadder(c.games.budget)
	// Scope is already an exact, selected per-game path; this never discovers or
	// captures a different application based on its basename.
	e.SetStartLocal(path.Base(gameudp.Canonical(executable)) == "tslgame.exe")
	return e
}
