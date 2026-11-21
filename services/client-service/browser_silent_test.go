package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func silentFixture(t *testing.T, edge bool) (*Controller, profiles.Profile, *string) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.BrowserOwnerSID = "S-1-test"
	if runtime.GOOS == "windows" {
		self, e := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
		if e != nil {
			t.Fatal(e)
		}
		sid, e := wp.ProcessUserSID(self)
		if e != nil {
			t.Fatal(e)
		}
		c.BrowserOwnerSID = sid
	}
	c.settings.Automatic = true
	exe := `C:\Apps\chrome.exe`
	method := "browser.prepare"
	if edge {
		exe = `C:\Apps\msedge.exe`
		method = "edge.prepare"
	}
	p := profiles.Profile{ID: "browser", Name: "browser", Mode: profiles.Direct, Custom: true, Executables: []string{exe}}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	value := ""
	write := func(_ string, owned []string, next string) error {
		if value != "" {
			ok := false
			for _, v := range owned {
				if v == value {
					ok = true
				}
			}
			if !ok {
				return errors.New("foreign policy")
			}
		}
		value = next
		return nil
	}
	active := func(_ string, pac string) bool { return value == edgePolicyValue(pac) }
	if edge {
		e := c.edgeLocked()
		e.write = write
		e.active = active
	} else {
		c.browser.chromeWrite = write
		c.browser.chromeActive = active
	}
	raw, _ := json.Marshal(map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": "127.0.0.1:54123"})
	var err error
	if edge {
		_, err = c.handleEdge(method, raw)
	} else {
		_, err = c.handleBrowser(method, raw)
	}
	if err != nil {
		t.Fatal(err)
	}
	return c, p, &value
}
func TestSilentPACPreparedIsNotBrowserUptakeOrNonceProof(t *testing.T) {
	for _, edge := range []bool{false, true} {
		t.Run(map[bool]string{false: "chrome", true: "edge"}[edge], func(t *testing.T) {
			c, p, _ := silentFixture(t, edge)
			method := "browser.silent.apply"
			if edge {
				method = "edge.silent.apply"
			}
			v, err := c.handleBrowserSilent(method, []byte(`{"profile_id":"browser"}`))
			if err != nil {
				t.Fatal(err)
			}
			got := v.(browserSilentView)
			if got.State != "POLICY_PENDING_BROWSER_REFRESH" || got.ApplyToRequestMS != -1 || len(got.ConfiguredProfiles) != 1 {
				t.Fatal(got)
			}
			server := c.browser.server
			if edge {
				server = c.browser.edge.server
			}
			if server.Confirmed(p.ID) {
				t.Fatal("silent apply forged actual browser nonce proof")
			}
			p.Mode = profiles.Auto
			if edge {
				p.AppPreset = "edge-sites"
			}
			c.Profiles.Upsert(p)
			if err := c.requireChromeActivation(); err != nil {
				t.Fatal("configured lane cannot arm", err)
			}
			if _, err := c.handleBrowserSilent(method, []byte(`{"profile_id":"other"}`)); err == nil {
				t.Fatal("foreign profile accepted")
			}
		})
	}
}
func TestSilentPACBootFreezeReapplyAndForeignPolicy(t *testing.T) {
	for _, edge := range []bool{false, true} {
		t.Run(map[bool]string{false: "chrome", true: "edge"}[edge], func(t *testing.T) {
			c, _, value := silentFixture(t, edge)
			// Restore publishes the real ACL-protected recovery guard. A dummy
			// SID works only on portable stubs, never on native Windows ACLs.
			if runtime.GOOS == "windows" {
				identity, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
				if err != nil {
					t.Fatal(err)
				}
				sid, err := wp.ProcessUserSID(identity)
				if err != nil {
					t.Fatal(err)
				}
				c.BrowserOwnerSID = sid
			}
			c.customPath = filepath.Join(t.TempDir(), "profiles.json")
			method := "browser.silent.apply"
			if edge {
				method = "edge.silent.apply"
			}
			if _, err := c.handleBrowserSilent(method, []byte(`{"profile_id":"browser"}`)); err != nil {
				t.Fatal(err)
			}
			owned := *value
			// New controller restores durable journal, not a fake browser proof. Same
			// port and owner writer; policy was erased by the club freeze image.
			c.Close()
			next := New(context.Background())
			defer next.Close()
			next.BrowserOwnerSID = c.BrowserOwnerSID
			next.customPath = c.customPath
			*value = ""
			if edge {
				e := next.edgeLocked()
				e.write = c.browser.edge.write
				e.active = c.browser.edge.active
				if err := next.loadEdgeTransport(); err != nil {
					t.Fatal(err)
				}
			} else {
				next.browser.chromeWrite = c.browser.chromeWrite
				next.browser.chromeActive = c.browser.chromeActive
				if err := next.RestoreBrowserTransport(); err != nil {
					t.Fatal(err)
				}
			}
			if *value != owned {
				t.Fatal("boot did not reapply owned PAC")
			}
			*value = "foreign-admin-policy"
			next.RetrySilentBrowserPolicies()
			if *value != "foreign-admin-policy" {
				t.Fatal("overwrote foreign policy")
			}
		})
	}
}
func TestSilentPACUptakeCountsOnlyCurrentOwnerProfileEpoch(t *testing.T) {
	c, p, _ := silentFixture(t, false)
	_, err := c.handleBrowserSilent("browser.silent.apply", []byte(`{"profile_id":"browser"}`))
	if err != nil {
		t.Fatal(err)
	}
	at := c.browser.silent.AppliedAt
	snap := browserproxy.Snapshot{Listening: true, Records: []browserproxy.Record{{Owner: browserproxy.Owner{Profile: p.ID}, Started: at.Add(75 * time.Millisecond)}, {Owner: browserproxy.Owner{Profile: "other"}, Started: at.Add(time.Millisecond)}, {Owner: browserproxy.Owner{Profile: p.ID}, Started: at.Add(-time.Second)}}}
	got := c.silentViewLocked(false, snap)
	if got.State != "PAC_REQUEST_OBSERVED" || got.ObservedRequests != 1 || got.ApplyToRequestMS != 75 {
		t.Fatal(got)
	}
}
func TestSilentPACCannotApplyBeforeListenerAndRecovery(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "S-1-test"
	c.Profiles.Upsert(profiles.Profile{ID: "browser", Mode: profiles.Direct, Executables: []string{"chrome.exe"}})
	if _, err := c.handleBrowserSilent("browser.silent.apply", []byte(`{"profile_id":"browser"}`)); err == nil {
		t.Fatal("unprepared PAC accepted")
	}
}
