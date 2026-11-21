package controlclient

import (
	"context"
	"github.com/buzzmean/neexitlag/core/traffic"
)

func (c *Client) RelayTraffic(ctx context.Context, token string, o traffic.Observation) error {
	_, e := c.request(ctx, "POST", "/api/v1/relays/traffic", o, token)
	return e
}
func (c *Client) RelayTrafficSnapshot(ctx context.Context) ([]byte, error) {
	return c.request(ctx, "GET", "/api/v1/relays/traffic", nil, "")
}
