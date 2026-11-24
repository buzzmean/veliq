package clientservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/buzzmean/veliq/core/gameudp"
	"github.com/buzzmean/veliq/core/security"
)

const cs2PreferenceFileLimit = 32 * 1024

// Owned only by the game observer's periodic loop. File I/O never takes the
// controller or engine lock.
type cs2DiskState struct {
	path      string
	saved     [sha256.Size]byte
	readError bool
}

type cs2PreferenceFile struct {
	Version     int                     `json:"version"`
	Application string                  `json:"application"`
	Routes      []gameudp.CS2Preference `json:"routes"`
}

func readCS2Preferences(file, image string, engine *gameudp.Engine, now time.Time) ([]byte, error) {
	in, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	raw, err := io.ReadAll(io.LimitReader(in, cs2PreferenceFileLimit+1))
	var d cs2PreferenceFile
	if err != nil || len(raw) > cs2PreferenceFileLimit || security.Parse(raw, &d) != nil || d.Version != 1 || d.Application != image {
		return nil, errors.New("CS2_PREFERENCE_FILE_INVALID")
	}
	if err = engine.RestoreCS2Preferences(image, d.Routes, now); err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *cs2DiskState) sync(dir, image string, engine *gameudp.Engine, now time.Time) string {
	image = gameudp.Canonical(image)
	pathKey := sha256.Sum256([]byte(image))
	file := filepath.Join(dir, "cs2-routes-"+hex.EncodeToString(pathKey[:16])+".json")
	if s.path != file {
		*s = cs2DiskState{path: file}
		raw, err := readCS2Preferences(file, image, engine, now)
		if err == nil {
			s.saved = sha256.Sum256(raw)
		} else if !os.IsNotExist(err) {
			s.readError = true
		}
	}
	rows := engine.CS2Preferences(now)
	if len(rows) == 0 && s.saved == ([sha256.Size]byte{}) {
		if s.readError {
			return "CS2_PREFERENCE_READ_FAILED"
		}
		return ""
	}
	raw, err := json.Marshal(cs2PreferenceFile{Version: 1, Application: image, Routes: rows})
	if err != nil || len(raw) > cs2PreferenceFileLimit {
		return "CS2_PREFERENCE_SIZE_INVALID"
	}
	digest := sha256.Sum256(raw)
	if digest != s.saved {
		if writeGameStateFile(file, raw) != nil {
			return "CS2_PREFERENCE_WRITE_FAILED"
		}
		s.saved = digest
		s.readError = false
	}
	return ""
}

func (c *Controller) syncCS2Preferences(now time.Time) {
	if c.customPath == "" {
		return
	}
	c.games.mu.Lock()
	var active []*gameEntry
	for _, g := range c.games.items {
		if g.CS2Auto && g.SteamCS2 {
			active = append(active, g)
		}
	}
	c.games.mu.Unlock()
	for _, g := range active {
		status := g.cs2Disk.sync(filepath.Dir(c.customPath), g.Path, g.Engine, now)
		c.games.mu.Lock()
		g.cs2DiskError = status
		c.games.mu.Unlock()
	}
}
