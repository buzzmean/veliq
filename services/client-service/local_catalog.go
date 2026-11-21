package clientservice

import (
	"context"
	"crypto/ed25519"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/localcatalog"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/originpolicy"
	"path/filepath"
	"sync"
	"time"
)

type catalogStatus struct {
	Source        string                      `json:"source"`
	Version       uint64                      `json:"version"`
	Schema        int                         `json:"schema"`
	Rules         int                         `json:"rules"`
	Unsupported   int                         `json:"unsupported"`
	Plans         []localstrategy.CatalogPlan `json:"plans"`
	LastCheck     time.Time                   `json:"last_check"`
	Error         string                      `json:"error,omitempty"`
	OriginVersion uint64                      `json:"origin_version"`
	OriginSource  string                      `json:"origin_source"`
	OriginRules   int                         `json:"origin_rules"`
	Activation    string                      `json:"activation"`
}
type clientCatalog struct {
	mu      sync.Mutex
	status  catalogStatus
	origins originpolicy.Registry
}

func newClientCatalog() *clientCatalog {
	c := &clientCatalog{}
	c.use(localstrategy.BundledCatalog(), 0, "BUNDLED_REVIEWED")
	return c
}
func (c *clientCatalog) use(data localstrategy.Catalog, version uint64, source string) {
	plans, caps := data.Compile()
	unsupported := 0
	for _, cap := range caps {
		if !cap.Supported {
			unsupported++
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	registry := originpolicy.Bundled()
	if data.Origins != nil {
		registry = *data.Origins
	}
	c.origins = registry
	c.status = catalogStatus{OriginVersion: registry.Version, OriginSource: registry.Source, OriginRules: len(registry.Rules), Source: source, Version: version, Schema: data.Version, Rules: len(data.Rules), Unsupported: unsupported, Plans: plans, LastCheck: c.status.LastCheck, Activation: "BOUNDED_SELECTION_CANDIDATES; availability is not transformed TLS health"}
}
func (c *clientCatalog) snapshot() catalogStatus { c.mu.Lock(); defer c.mu.Unlock(); return c.status }
func (c *clientCatalog) check(err string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.LastCheck = time.Now().UTC()
	c.status.Error = err
}
func (c *clientCatalog) run(ctx context.Context, cp *controlclient.Client, keys map[string]ed25519.PublicKey, state string) {
	path := ""
	if state != "" {
		path = filepath.Join(state, "signed-local-catalog.json")
	}
	cache := localcatalog.New(keys, path)
	_ = cache.Load(time.Now())
	poll := func() {
		if d, err := cache.Current(time.Now()); err == nil {
			c.use(d.Catalog, d.Version, "SIGNED_LAST_KNOWN_GOOD")
		} else {
			c.use(localstrategy.BundledCatalog(), 0, "BUNDLED_REVIEWED")
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		raw, err := cp.LocalCatalog(work)
		cancel()
		if err == nil {
			err = cache.Apply(raw, time.Now())
		}
		if err != nil {
			c.check("CATALOG_CP_UNAVAILABLE_OR_REJECTED; current reviewed data retained")
			return
		}
		d, err := cache.Current(time.Now())
		if err != nil {
			c.check("CATALOG_EXPIRED")
			return
		}
		c.use(d.Catalog, d.Version, "SIGNED_CONTROL_PLANE")
		c.check("")
	}
	poll()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

func (c *clientCatalog) origin(host string) originpolicy.Rule {
	floor := originpolicy.Floor(host)
	if floor.Kind == "RELAY" {
		return floor
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.origins.Lookup(host)
}
