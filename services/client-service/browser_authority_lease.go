package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net/netip"
	"os"
	"path/filepath"
)

type ownerProxyExchange func(context.Context, wp.OwnerProxyCommand) (wp.OwnerProxyState, error)
type ownerProxyLease struct {
	Version   int                 `json:"version"`
	Owner     string              `json:"owner"`
	Original  wp.OwnerProxyState  `json:"original"`
	Installed wp.OwnerProxyState  `json:"installed"`
	Previous  *wp.OwnerProxyState `json:"previous,omitempty"`
}

func readOwnerProxyLease(path, owner string) (*ownerProxyLease, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() > 512*1024 {
		return nil, errors.New("OWNER_PROXY_JOURNAL_UNAVAILABLE")
	}
	raw, err := os.ReadFile(path)
	var lease ownerProxyLease
	if err != nil || json.Unmarshal(raw, &lease) != nil || lease.Version != 1 || lease.Owner != owner || !freeOwnerProxy(lease.Original) || !ownedAuthorityProxy(lease.Installed) {
		return nil, errors.New("OWNER_PROXY_JOURNAL_INVALID")
	}
	if lease.Previous != nil && !ownedAuthorityProxy(*lease.Previous) {
		return nil, errors.New("OWNER_PROXY_JOURNAL_INVALID")
	}
	return &lease, nil
}
func ownedAuthorityProxy(s wp.OwnerProxyState) bool {
	if s.Bypass != "" || !validAuthorityPAC(s.PAC) {
		return false
	}
	if s.Flags == 5 && s.Server == "" {
		return true
	} // Existing journal from the first isolated proof.
	address, err := netip.ParseAddrPort(s.Server)
	return s.Flags == 7 && err == nil && address.Addr() == netip.MustParseAddr("127.0.0.1") && address.Port() != 0
}
func freeOwnerProxy(s wp.OwnerProxyState) bool {
	return s.PAC == "" && s.Server == "" && s.Flags&2 == 0
}
func writeOwnerProxyLease(path string, lease ownerProxyLease) error {
	raw, err := json.Marshal(lease)
	if err != nil {
		return errors.New("OWNER_PROXY_JOURNAL_WRITE_FAILED")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".owner-proxy-")
	if err != nil {
		return errors.New("OWNER_PROXY_JOURNAL_WRITE_FAILED")
	}
	name := f.Name()
	defer os.Remove(name)
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
		err = os.Rename(name, path)
	}
	if err != nil {
		return errors.New("OWNER_PROXY_JOURNAL_WRITE_FAILED")
	}
	return nil
}

// Persist before mutation, so a process crash at any instruction is recoverable.
// Compare-before-write is not an atomic Windows transaction; foreign changes
// seen before a write or during readback are refused and never blindly restored.
func acquireOwnerProxy(ctx context.Context, path, owner, pac string, exchange ownerProxyExchange) error {
	return acquireOwnerProxyState(ctx, path, owner, wp.OwnerProxyState{Flags: 5, PAC: pac}, exchange)
}
func acquireOwnerProxyState(ctx context.Context, path, owner string, desired wp.OwnerProxyState, exchange ownerProxyExchange) error {
	if !ownedAuthorityProxy(desired) {
		return errors.New("OWNER_PROXY_PAC_INVALID")
	}
	lease, err := readOwnerProxyLease(path, owner)
	if err != nil {
		return err
	}
	current, err := exchange(ctx, wp.OwnerProxyCommand{Owner: owner})
	if err != nil {
		return err
	}
	if lease == nil {
		if !freeOwnerProxy(current) {
			return errors.New("OWNER_PROXY_FOREIGN_PRESERVED")
		}
		lease = &ownerProxyLease{Version: 1, Owner: owner, Original: current}
	} else if current != lease.Installed && current != lease.Original && (lease.Previous == nil || current != *lease.Previous) {
		return errors.New("OWNER_PROXY_FOREIGN_PRESERVED")
	}
	if current == desired {
		return nil
	}
	lease.Installed = desired
	lease.Previous = nil
	if current != lease.Original {
		previous := current
		lease.Previous = &previous
	}
	if err := writeOwnerProxyLease(path, *lease); err != nil {
		return err
	}
	actual, err := exchange(ctx, wp.OwnerProxyCommand{Owner: owner, Expected: &current, Desired: &desired})
	if err != nil {
		return err
	}
	if actual != desired {
		return errors.New("OWNER_PROXY_READBACK_MISMATCH")
	}
	return nil
}
func releaseOwnerProxy(ctx context.Context, path, owner string, exchange ownerProxyExchange) error {
	lease, err := readOwnerProxyLease(path, owner)
	if err != nil || lease == nil {
		return err
	}
	current, err := exchange(ctx, wp.OwnerProxyCommand{Owner: owner})
	if err != nil {
		return err
	}
	if current != lease.Original {
		if current != lease.Installed && (lease.Previous == nil || current != *lease.Previous) {
			return errors.New("OWNER_PROXY_FOREIGN_PRESERVED")
		}
		actual, err := exchange(ctx, wp.OwnerProxyCommand{Owner: owner, Expected: &current, Desired: &lease.Original})
		if err != nil {
			return err
		}
		if actual != lease.Original {
			return errors.New("OWNER_PROXY_RESTORE_READBACK_MISMATCH")
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return errors.New("OWNER_PROXY_JOURNAL_REMOVE_FAILED")
	}
	return nil
}
