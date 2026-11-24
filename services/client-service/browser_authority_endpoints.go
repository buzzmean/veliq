package clientservice

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Addresses survive a deliberate stop/update independently of the reversible
// Windows settings lease. The installation's protected state directory owns
// this file; neither IPC nor a caller-supplied port can add an endpoint.
type ownerAuthorityEndpoints struct {
	Version       int      `json:"version"`
	Owner         string   `json:"owner"`
	Primary       string   `json:"primary"`
	Compatibility []string `json:"compatibility,omitempty"`
}

func authorityEndpointsPath(directory string) string {
	return filepath.Join(directory, "browser-owner-endpoints.json")
}

func validAuthorityEndpoints(v ownerAuthorityEndpoints, owner string) bool {
	if v.Version != 1 || owner == "" || v.Owner != owner || v.Primary == "" || authorityServerAddress(v.Primary) != v.Primary || len(v.Compatibility) > 1 {
		return false
	}
	for _, address := range v.Compatibility {
		if address == v.Primary || address == "" || authorityServerAddress(address) != address {
			return false
		}
	}
	return true
}

func readAuthorityEndpoints(directory, owner string) (*ownerAuthorityEndpoints, error) {
	path := authorityEndpointsPath(directory)
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
		return nil, errors.New("OWNER_PROXY_ENDPOINTS_UNAVAILABLE")
	}
	raw, err := os.ReadFile(path)
	var v ownerAuthorityEndpoints
	if err != nil || json.Unmarshal(raw, &v) != nil || !validAuthorityEndpoints(v, owner) {
		return nil, errors.New("OWNER_PROXY_ENDPOINTS_INVALID")
	}
	return &v, nil
}

func writeAuthorityEndpoints(directory string, v ownerAuthorityEndpoints) error {
	if !validAuthorityEndpoints(v, v.Owner) {
		return errors.New("OWNER_PROXY_ENDPOINTS_INVALID")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return errors.New("OWNER_PROXY_ENDPOINTS_WRITE_FAILED")
	}
	if old, err := os.ReadFile(authorityEndpointsPath(directory)); err == nil && string(old) == string(raw) {
		return nil
	}
	f, err := os.CreateTemp(directory, ".owner-endpoints-")
	if err != nil {
		return errors.New("OWNER_PROXY_ENDPOINTS_WRITE_FAILED")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
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
		err = os.Rename(f.Name(), authorityEndpointsPath(directory))
	}
	if err != nil {
		return errors.New("OWNER_PROXY_ENDPOINTS_WRITE_FAILED")
	}
	return nil
}

func authorityLeaseEndpoint(lease *ownerProxyLease) string {
	if lease == nil {
		return ""
	}
	if lease.Installed.PAC != "" {
		return authorityAddress(lease.Installed.PAC)
	}
	return authorityServerAddress(lease.Installed.Server)
}

// Import only bounded, same-owner lease records, never arbitrary addresses.
// The current lease always wins as primary. Older addresses are compatibility
// listeners only and cannot rewrite the owner's system proxy.
func prepareAuthorityEndpoints(directory, owner, previousLeasePath string) error {
	state, err := readAuthorityEndpoints(directory, owner)
	if err != nil {
		return err
	}
	lease, err := readOwnerProxyLease(filepath.Join(directory, "browser-owner-proxy.json"), owner)
	if err != nil {
		return err
	}
	primary := authorityLeaseEndpoint(lease)
	if primary == "" {
		if previousLeasePath != "" {
			return errors.New("OWNER_PROXY_CURRENT_LEASE_REQUIRED")
		}
		return nil // Fresh install, or persisted addresses already survive a stop.
	}
	next := ownerAuthorityEndpoints{Version: 1, Owner: owner, Primary: primary}
	add := func(address string) error {
		if address == "" || address == next.Primary {
			return nil
		}
		for _, old := range next.Compatibility {
			if old == address {
				return nil
			}
		}
		if len(next.Compatibility) >= 1 {
			return errors.New("OWNER_PROXY_ENDPOINT_LIMIT")
		}
		next.Compatibility = append(next.Compatibility, address)
		return nil
	}
	if state != nil {
		if err := add(state.Primary); err != nil {
			return err
		}
		for _, address := range state.Compatibility {
			if err := add(address); err != nil {
				return err
			}
		}
	}
	if lease.Previous != nil {
		old := *lease
		old.Installed = *lease.Previous
		if err := add(authorityLeaseEndpoint(&old)); err != nil {
			return err
		}
	}
	if previousLeasePath != "" {
		previous, err := readOwnerProxyLease(previousLeasePath, owner)
		if err != nil || previous == nil {
			return errors.New("OWNER_PROXY_PREVIOUS_LEASE_INVALID")
		}
		if err := add(authorityLeaseEndpoint(previous)); err != nil {
			return err
		}
	}
	return writeAuthorityEndpoints(directory, next)
}

// PrepareOwnerAuthorityEndpoints runs in the elevated installer before stopping
// an older service that deletes its reversible lease. No network/listeners,
// activation or Windows proxy settings are changed by this operation.
func PrepareOwnerAuthorityEndpoints(manifestPath, previousLeasePath string) error {
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	return prepareAuthorityEndpoints(manifest.StateDirectory, manifest.OwnerSID, previousLeasePath)
}
