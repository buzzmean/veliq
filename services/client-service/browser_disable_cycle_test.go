package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/veliq/core/browserproxy"
	wp "github.com/buzzmean/veliq/platform/windows"
	"os"
	"path/filepath"
	"testing"
)

type guardStartFixture struct {
	activationCaptureFixture
	check func()
}

func (b *guardStartFixture) Start(ctx context.Context, cl wp.Classifier) error {
	b.check()
	return b.activationCaptureFixture.Start(ctx, cl)
}
func TestDisabledRecoveryGrantRevokedBeforeCaptureRestarts(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	c.settings.Automatic = true
	c.browser.readiness.enforced.Store(true)
	read := func() browserproxy.RecoveryGuard {
		t.Helper()
		raw, e := os.ReadFile(c.browserGuardFile())
		if e != nil {
			t.Fatal(e)
		}
		var g browserproxy.RecoveryGuard
		if json.Unmarshal(raw, &g) != nil {
			t.Fatal("invalid guard")
		}
		return g
	}
	b := &guardStartFixture{check: func() {
		g := read()
		if !g.Deny || g.DirectCompatibility {
			t.Fatal("disabled grant survived capture start", g)
		}
	}}
	c.Backend = b
	if _, e := c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); e != nil {
		t.Fatal(e)
	}
	if g := read(); !g.DirectCompatibility || g.Deny {
		t.Fatal("off grant missing", g)
	}
	if _, e := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); e != nil {
		t.Fatal(e)
	}
	if g := read(); g.DirectCompatibility || g.Deny {
		t.Fatal("active guard wrong", g)
	}
}
