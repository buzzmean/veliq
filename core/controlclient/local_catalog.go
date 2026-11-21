package controlclient

import "context"

// Separate signed document: old strict config consumers are not given new fields.
// A legacy CP's 404 leaves the compiled-in reviewed catalog in use.
func (c *Client) LocalCatalog(ctx context.Context) ([]byte, error) {
	return c.request(ctx, "GET", "/api/v1/local/catalog", nil, "")
}
