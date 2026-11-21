// Package localcatalog distributes bounded, signed packet-plan DATA. It never
// executes source scripts or changes authentication/routing authorization.
package localcatalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/security"
)

const Domain = "local-catalog"

type Document struct {
	Version     uint64                `json:"version"`
	GeneratedAt time.Time             `json:"generated_at"`
	ExpiresAt   time.Time             `json:"expires_at"`
	Catalog     localstrategy.Catalog `json:"catalog"`
}

func Validate(keys map[string]ed25519.PublicKey, raw []byte, now time.Time) (Document, error) {
	var d Document
	if err := security.Verify(Domain, keys, raw, &d); err != nil {
		return d, err
	}
	if d.Version == 0 || d.GeneratedAt.After(now.Add(30*time.Second)) || !d.ExpiresAt.After(now) || !d.ExpiresAt.After(d.GeneratedAt) || d.ExpiresAt.Sub(d.GeneratedAt) > 48*time.Hour {
		return d, errors.New("LOCAL_CATALOG_EXPIRED_OR_INVALID")
	}
	b, err := json.Marshal(d.Catalog)
	if err != nil {
		return d, err
	}
	if _, err = localstrategy.ParseCatalog(b); err != nil {
		return d, err
	}
	return d, nil
}

type Cache struct {
	mu   sync.Mutex
	keys map[string]ed25519.PublicKey
	path string
	doc  Document
	hash [32]byte
}

func New(keys map[string]ed25519.PublicKey, path string) *Cache {
	k := map[string]ed25519.PublicKey{}
	for id, key := range keys {
		k[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Cache{keys: k, path: path}
}
func (c *Cache) Apply(raw []byte, now time.Time) error {
	doc, err := Validate(c.keys, raw, now)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(doc.Catalog)
	hash := sha256.Sum256(data)
	c.mu.Lock()
	defer c.mu.Unlock()
	if doc.Version < c.doc.Version || doc.Version == c.doc.Version && c.doc.Version != 0 && hash != c.hash || doc.GeneratedAt.Before(c.doc.GeneratedAt) {
		return errors.New("LOCAL_CATALOG_ROLLBACK_OR_EQUIVOCATION")
	}
	if c.path != "" {
		if err = os.MkdirAll(filepath.Dir(c.path), 0700); err != nil {
			return err
		}
		old, readErr := os.ReadFile(c.path)
		if readErr != nil || !bytes.Equal(old, raw) {
			f, e := os.CreateTemp(filepath.Dir(c.path), ".local-catalog-*")
			if e != nil {
				return e
			}
			name := f.Name()
			defer os.Remove(name)
			if e = f.Chmod(0600); e == nil {
				_, e = f.Write(raw)
			}
			if e == nil {
				e = f.Sync()
			}
			closeErr := f.Close()
			if e == nil {
				e = closeErr
			}
			if e != nil {
				return e
			}
			if e = os.Rename(name, c.path); e != nil {
				return e
			}
		}
	}
	c.doc, c.hash = doc, hash
	return nil
}
func (c *Cache) Load(now time.Time) error {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	return c.Apply(raw, now)
}
func (c *Cache) Current(now time.Time) (Document, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.doc.Version == 0 || !c.doc.ExpiresAt.After(now) {
		return Document{}, errors.New("LOCAL_CATALOG_UNAVAILABLE")
	}
	raw, _ := json.Marshal(c.doc)
	var d Document
	json.Unmarshal(raw, &d)
	return d, nil
}
