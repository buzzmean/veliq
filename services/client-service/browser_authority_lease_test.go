package clientservice

import (
	"context"
	"errors"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"os"
	"path/filepath"
	"testing"
)

func authorityLeaseFixture(t *testing.T) (string, string, *wp.OwnerProxyState, ownerProxyExchange) {
	t.Helper()
	pac, err := authorityPAC("127.0.0.1:12345", "0123456789abcdef", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	state := &wp.OwnerProxyState{Flags: 9, Bypass: "original-disabled-bypass"}
	exchange := func(_ context.Context, q wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
		if q.Owner != "owner" {
			return wp.OwnerProxyState{}, errors.New("wrong owner")
		}
		if q.Desired != nil {
			if *state != *q.Expected {
				return *state, errors.New("foreign changed")
			}
			*state = *q.Desired
		}
		return *state, nil
	}
	return filepath.Join(t.TempDir(), "lease.json"), pac, state, exchange
}
func TestAuthorityLeaseRestoresFullOriginalAndPreservesForeign(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "foreign"}[foreign], func(t *testing.T) {
			path, pac, state, exchange := authorityLeaseFixture(t)
			original := *state
			if err := acquireOwnerProxy(context.Background(), path, "owner", pac, exchange); err != nil {
				t.Fatal(err)
			}
			if authorityAddress(state.PAC) != "127.0.0.1:12345" {
				t.Fatal("owned PAC endpoint missing")
			}
			if err := acquireOwnerProxy(context.Background(), path, "owner", pac, exchange); err != nil {
				t.Fatal("idempotent", err)
			}
			if foreign {
				state.PAC = "https://foreign.invalid/proxy.pac"
			}
			before := *state
			err := releaseOwnerProxy(context.Background(), path, "owner", exchange)
			if foreign {
				if err == nil || *state != before {
					t.Fatal("foreign proxy changed")
				}
				return
			}
			if err != nil || *state != original {
				t.Fatal("full original not restored", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("journal not removed")
			}
		})
	}
}
func TestAuthorityLeaseCrashBeforeDuringAndAfterUpdate(t *testing.T) {
	for _, stage := range []string{"before-first-write", "after-first-write", "before-update", "after-update"} {
		t.Run(stage, func(t *testing.T) {
			path, pac, state, exchange := authorityLeaseFixture(t)
			original := *state
			crash := func(ctx context.Context, q wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
				if q.Desired != nil {
					if stage == "after-first-write" || stage == "after-update" {
						_, _ = exchange(ctx, q)
					}
					return wp.OwnerProxyState{}, errors.New("simulated process death")
				}
				return exchange(ctx, q)
			}
			if stage == "before-update" || stage == "after-update" {
				if err := acquireOwnerProxy(context.Background(), path, "owner", pac, exchange); err != nil {
					t.Fatal(err)
				}
				pac, _ = authorityPAC("127.0.0.1:12345", "new-epoch", []string{"new-guard.invalid"}, false)
			}
			if err := acquireOwnerProxy(context.Background(), path, "owner", pac, crash); err == nil {
				t.Fatal("simulated crash ignored")
			}
			if err := releaseOwnerProxy(context.Background(), path, "owner", exchange); err != nil || *state != original {
				t.Fatal("crash left owned proxy", err)
			}
		})
	}
}
func TestAuthorityLeaseRefusesForeignAndCorruptJournalBeforeMutation(t *testing.T) {
	for _, scenario := range []string{"foreign-pac", "foreign-manual", "corrupt", "other-owner", "write-failed"} {
		t.Run(scenario, func(t *testing.T) {
			path, pac, state, exchange := authorityLeaseFixture(t)
			switch scenario {
			case "foreign-pac":
				state.PAC = "https://foreign.invalid"
			case "foreign-manual":
				state.Server = "127.0.0.1:8"
				state.Flags = 3
			case "corrupt":
				os.WriteFile(path, []byte(`{`), 0600)
			case "other-owner":
				other := ownerProxyLease{Version: 1, Owner: "other", Original: *state, Installed: wp.OwnerProxyState{Flags: 5, PAC: pac}}
				writeOwnerProxyLease(path, other)
			case "write-failed":
				path = filepath.Join(path, "missing", "lease.json")
			}
			before := *state
			if err := acquireOwnerProxy(context.Background(), path, "owner", pac, exchange); err == nil || *state != before {
				t.Fatal("unsafe mutation")
			}
		})
	}
}
