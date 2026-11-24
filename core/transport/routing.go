package transport

import (
	"context"
	"github.com/buzzmean/veliq/core/routing"
	"net/netip"
)

// OpenDatagram adapts the typed relay client to routing's provider contract.
func (c *Client) OpenDatagram(ctx context.Context, dst netip.AddrPort) (routing.Datagram, error) {
	f, err := c.OpenUDP(ctx, dst)
	if err != nil {
		return nil, err
	}
	return f, nil
}
