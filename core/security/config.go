package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/profiles"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Config struct {
	Version             uint64                     `json:"version"`
	GeneratedAt         time.Time                  `json:"generated_at"`
	ExpiresAt           time.Time                  `json:"expires_at"`
	Relays              []optimizer.RelayCandidate `json:"relays"`
	ApplicationProfiles []profiles.Profile         `json:"application_profiles"`
	RoutingParameters   optimizer.Parameters       `json:"routing_parameters"`
	PublicKeys          map[string]string          `json:"public_keys"`
	RevokedDevices      []string                   `json:"revoked_devices,omitempty"`
	ClientVersion       string                     `json:"client_version"`
}

func ValidateConfig(keys map[string]ed25519.PublicKey, raw []byte, now time.Time) (Config, error) {
	var c Config
	if e := Verify("config", keys, raw, &c); e != nil {
		return c, e
	}
	if c.Version == 0 || !c.ExpiresAt.After(now) || c.GeneratedAt.After(now.Add(30*time.Second)) || !c.ExpiresAt.After(c.GeneratedAt) || c.ExpiresAt.Sub(c.GeneratedAt) > 48*time.Hour || len(c.Relays) > 32 || len(c.ApplicationProfiles) > 128 {
		return c, errors.New("invalid or expired configuration")
	}
	if e := optimizer.ValidateParameters(c.RoutingParameters); e != nil {
		return c, e
	}
	seen := map[string]bool{}
	for _, r := range c.Relays {
		if r.ID == "" || seen[r.ID] || r.Address == "" {
			return c, errors.New("invalid relay registry")
		}
		seen[r.ID] = true
	}
	for _, p := range c.ApplicationProfiles {
		if e := p.Validate(); e != nil {
			return c, e
		}
	}
	for _, k := range c.PublicKeys {
		if _, e := DecodePublicKey(k); e != nil {
			return c, e
		}
	}
	return c, nil
}

type ConfigCache struct {
	mu     sync.Mutex
	Keys   map[string]ed25519.PublicKey
	Path   string
	config Config
	raw    []byte
	hash   string
}

func NewConfigCache(keys map[string]ed25519.PublicKey, path string) *ConfigCache {
	return &ConfigCache{Keys: copyKeys(keys), Path: path}
}
func (c *ConfigCache) Apply(raw []byte, now time.Time) error {
	cfg, e := ValidateConfig(c.Keys, raw, now)
	if e != nil {
		return e
	}
	var env Envelope
	if e = parseLimit(raw, &env, MaxConfigDocument); e != nil {
		return e
	}
	h := sha256.Sum256(env.Payload)
	hash := hex.EncodeToString(h[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg.Version < c.config.Version || cfg.Version == c.config.Version && hash != c.hash {
		return errors.New("config rollback or equivocation")
	}
	if c.Path != "" {
		if e = os.MkdirAll(filepath.Dir(c.Path), 0700); e != nil {
			return e
		}
		f, e := os.CreateTemp(filepath.Dir(c.Path), ".config-*")
		if e != nil {
			return e
		}
		name := f.Name()
		defer os.Remove(name)
		f.Chmod(0600)
		if _, e = f.Write(raw); e == nil {
			e = f.Sync()
		}
		f.Close()
		if e != nil {
			return e
		}
		if e = os.Rename(name, c.Path); e != nil {
			return e
		}
	}
	c.config = cfg
	c.raw = append([]byte(nil), raw...)
	c.hash = hash
	return nil
}
func (c *ConfigCache) Load(now time.Time) error {
	b, e := os.ReadFile(c.Path)
	if e != nil {
		return e
	}
	return c.Apply(b, now)
}
func (c *ConfigCache) Current(now time.Time) (Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.Version == 0 || !c.config.ExpiresAt.After(now) {
		return Config{}, errors.New("no valid Last Known Good config")
	}
	b, _ := json.Marshal(c.config)
	var out Config
	json.Unmarshal(b, &out)
	return out, nil
}
