package clientservice

import (
	"github.com/buzzmean/veliq/core/gameudp"
)

func (c *Controller) newGameLadder(_ string) *gameudp.Engine {
	e := gameudp.NewLadder(c.games.budget)
	e.SetEndpointScoped()
	return e
}
