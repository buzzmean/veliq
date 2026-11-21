package windowsplatform

import (
	"errors"
	"sync"
	"time"
)

type CachedProcess struct {
	Identity ProcessIdentity `json:"identity"`
	LastSeen time.Time       `json:"last_seen"`
}

// A PID is a lookup key, never a durable identity. Every hit checks creation time.
type ProcessCache struct {
	mu      sync.Mutex
	source  Discovery
	current func(ProcessIdentity) bool
	entries map[uint32]CachedProcess
	limit   int
	ttl     time.Duration
}

func NewProcessCache(source Discovery, current func(ProcessIdentity) bool) *ProcessCache {
	return &ProcessCache{source: source, current: current, entries: map[uint32]CachedProcess{}, limit: 4096, ttl: 2 * time.Minute}
}
func (c *ProcessCache) Lookup(pid uint32) (ProcessIdentity, error) {
	c.mu.Lock()
	old, ok := c.entries[pid]
	c.mu.Unlock()
	now := time.Now()
	if ok && now.Sub(old.LastSeen) < c.ttl && c.current != nil && c.current(old.Identity) {
		c.mu.Lock()
		old.LastSeen = now
		c.entries[pid] = old
		c.mu.Unlock()
		return old.Identity, nil
	}
	identity, err := c.source.Lookup(pid)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	if identity.PID != pid || identity.CreationTime == 0 || identity.Path == "" {
		return ProcessIdentity{}, errors.New("incomplete process identity")
	}
	if len(c.entries) >= c.limit {
		for p, v := range c.entries {
			if now.Sub(v.LastSeen) >= c.ttl {
				delete(c.entries, p)
			}
		}
	}
	if len(c.entries) < c.limit {
		c.entries[pid] = CachedProcess{identity, now}
	}
	return identity, nil
}
func (c *ProcessCache) Cleanup(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid, v := range c.entries {
		if now.Sub(v.LastSeen) >= c.ttl {
			delete(c.entries, pid)
		}
	}
}
