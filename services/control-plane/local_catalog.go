package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/buzzmean/neexitlag/core/localcatalog"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/security"
)

type localCatalogRelease struct {
	Version uint64                `json:"version"`
	Catalog localstrategy.Catalog `json:"catalog"`
}

func (a *API) readLocalCatalog() (localCatalogRelease, error) {
	fallback := localCatalogRelease{Version: localstrategy.BundledCatalogRelease, Catalog: localstrategy.BundledCatalog()}
	if a.Settings.LocalCatalogFile == "" {
		return fallback, nil
	}
	info, err := os.Lstat(a.Settings.LocalCatalogFile)
	if os.IsNotExist(err) {
		return fallback, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > security.MaxDocument {
		return localCatalogRelease{}, errors.New("LOCAL_CATALOG_FILE_INVALID")
	}
	raw, err := os.ReadFile(a.Settings.LocalCatalogFile)
	if err != nil {
		return localCatalogRelease{}, err
	}
	var r localCatalogRelease
	if security.Parse(raw, &r) != nil || r.Version == 0 {
		return r, errors.New("LOCAL_CATALOG_RELEASE_INVALID")
	}
	data, _ := json.Marshal(r.Catalog)
	if _, err = localstrategy.ParseCatalog(data); err != nil {
		return r, err
	}
	return r, nil
}
func (a *API) localCatalog(w http.ResponseWriter, r *http.Request) {
	a.localCatalogMu.Lock()
	defer a.localCatalogMu.Unlock()
	release, err := a.readLocalCatalog()
	if err != nil {
		a.fail(w, 503, "LOCAL_CATALOG_READ_FAILED")
		return
	}
	if r.Method == "PUT" {
		if !a.admin(r) {
			a.fail(w, 401, "administrator required")
			return
		}
		if a.Settings.LocalCatalogFile == "" {
			a.fail(w, 503, "LOCAL_CATALOG_PERSISTENCE_NOT_CONFIGURED")
			return
		}
		var next localCatalogRelease
		if body(r, &next) != nil || next.Version <= release.Version || next.Version <= localstrategy.BundledCatalogRelease {
			a.fail(w, 400, "LOCAL_CATALOG_NEW_VERSION_REQUIRED")
			return
		}
		raw, _ := json.Marshal(next.Catalog)
		if _, err = localstrategy.ParseCatalog(raw); err != nil {
			a.fail(w, 400, "LOCAL_CATALOG_INVALID")
			return
		}
		test := localcatalog.Document{Version: next.Version, GeneratedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(24 * time.Hour), Catalog: next.Catalog}
		if _, err = security.Sign(localcatalog.Domain, a.Settings.KeyID, a.Settings.SigningKey, test); err != nil {
			a.fail(w, 400, "LOCAL_CATALOG_SIGNED_SIZE_LIMIT")
			return
		}
		raw, _ = json.Marshal(next)
		path := a.Settings.LocalCatalogFile
		if err = os.MkdirAll(filepath.Dir(path), 0700); err == nil {
			var f *os.File
			f, err = os.CreateTemp(filepath.Dir(path), ".catalog-*")
			if err == nil {
				name := f.Name()
				defer os.Remove(name)
				err = f.Chmod(0600)
				if err == nil {
					_, err = f.Write(raw)
				}
				if err == nil {
					err = f.Sync()
				}
				closeErr := f.Close()
				if err == nil {
					err = closeErr
				}
				if err == nil {
					err = os.Rename(name, path)
				}
			}
		}
		if err != nil {
			a.fail(w, 503, "LOCAL_CATALOG_PERSIST_FAILED")
			return
		}
		release = next
	} else if r.Method != "GET" {
		a.fail(w, 405, "method not allowed")
		return
	}
	now := time.Now().UTC().Truncate(10 * time.Minute)
	raw, err := security.Sign(localcatalog.Domain, a.Settings.KeyID, a.Settings.SigningKey, localcatalog.Document{Version: release.Version, GeneratedAt: now, ExpiresAt: now.Add(24 * time.Hour), Catalog: release.Catalog})
	if err != nil {
		a.fail(w, 500, "LOCAL_CATALOG_SIGNING_FAILED")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}
