package clientservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func managedUpdaterFixture(t *testing.T) (*updater, *[]string) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	u, launched := newTestUpdater(t, updateFixture(t, 120, key, []byte("MZ managed fixture")), pub, "100")
	u.isClub = func() bool { return true } // No club-mode.json on account-linked PCs.
	u.managedPolicy = func() (bool, error) { return true, nil }
	u.launchManaged = u.launch
	return u, launched
}

func TestManagedUpdaterActiveClubInstallsAndGuestCannotTrigger(t *testing.T) {
	u, _ := managedUpdaterFixture(t)
	var personal, managed int
	u.launch = func(string) error { personal++; return nil }
	u.launchManaged = func(string) error { managed++; return nil }
	u.check(context.Background())
	if managed != 1 || personal != 0 || u.snapshot().State != "INSTALLING" || !u.snapshot().Managed {
		t.Fatal(u.snapshot(), managed, personal)
	}
	if u.install(120) == nil {
		t.Fatal("guest install accepted")
	}
	u.installExited()
	u.check(context.Background())
	if managed != 1 || u.snapshot().Error != "UPDATE_AUTO_ATTEMPT_RECORDED" {
		t.Fatal("timer relaunched failed Setup", u.snapshot(), managed)
	}
}

func TestManagedUpdaterClaimSurvivesRestartAndLaunchFailure(t *testing.T) {
	u, _ := managedUpdaterFixture(t)
	var calls atomic.Int32
	u.launchManaged = func(string) error { calls.Add(1); return errors.New("synthetic Start failure") }
	u.check(context.Background())
	if u.snapshot().Error != "UPDATE_LAUNCH_FAILED" {
		t.Fatal(u.snapshot())
	}
	restarted := newUpdater(u.keys, u.dir, u.launchManaged)
	restarted.current, restarted.api, restarted.http = u.current, u.api, u.http
	restarted.isClub, restarted.managedPolicy = u.isClub, u.managedPolicy
	restarted.check(context.Background())
	if calls.Load() != 1 || restarted.snapshot().Error != "UPDATE_AUTO_ATTEMPT_RECORDED" {
		t.Fatal("restart loop", restarted.snapshot(), calls.Load())
	}
}

func TestManagedUpdaterIndependentInstancesClaimOneLaunch(t *testing.T) {
	u, _ := managedUpdaterFixture(t)
	u.managedPolicy = func() (bool, error) { return false, nil }
	// Prepare via personal/manual flow, then switch to a managed club.
	u.isClub = func() bool { return false }
	u.check(context.Background())
	v := newUpdater(u.keys, u.dir, nil)
	v.current, v.ready, v.readyPath = u.current, u.ready, u.readyPath
	v.set("READY", "", &v.ready)
	u.isClub, v.isClub = func() bool { return true }, func() bool { return true }
	u.managedPolicy, v.managedPolicy = func() (bool, error) { return true, nil }, func() (bool, error) { return true, nil }
	var calls atomic.Int32
	launch := func(string) error { calls.Add(1); return nil }
	u.launchManaged, v.launchManaged = launch, launch
	var wg sync.WaitGroup
	for _, candidate := range []*updater{u, v} {
		wg.Add(1)
		go func(x *updater) { defer wg.Done(); x.op.Lock(); defer x.op.Unlock(); _ = x.installManagedLocked() }(candidate)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate process launch", calls.Load())
	}
}

func TestManagedUpdaterMissingInvalidAndWithdrawnPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy func() (bool, error)
		reason string
	}{
		{"disabled", func() (bool, error) { return false, nil }, "CLUB_IMAGE_MANAGED"},
		{"untrusted", func() (bool, error) { return false, errors.New("untrusted") }, "UPDATE_POLICY_UNTRUSTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, launched := managedUpdaterFixture(t)
			u.managedPolicy = tc.policy
			u.check(context.Background())
			if len(*launched) != 0 || u.snapshot().Error != tc.reason {
				t.Fatal(u.snapshot())
			}
		})
	}
	u, launched := managedUpdaterFixture(t)
	calls := 0
	u.managedPolicy = func() (bool, error) { calls++; return calls == 1, nil }
	u.check(context.Background())
	if len(*launched) != 0 || u.snapshot().State != "DISABLED" {
		t.Fatal("policy withdrawn during download still applied", u.snapshot())
	}
}

func TestManagedUpdaterPersonalRemainsManualWithoutAdministratorOptIn(t *testing.T) {
	u, launched := managedUpdaterFixture(t)
	u.isClub = func() bool { return false }
	u.managedPolicy = func() (bool, error) { return false, nil }
	u.check(context.Background())
	if len(*launched) != 0 || u.snapshot().Managed || u.snapshot().State != "READY" {
		t.Fatal(u.snapshot())
	}
}

func TestManagedUpdaterAdministratorOptInDoesNotRequireClubImage(t *testing.T) {
	u, launched := managedUpdaterFixture(t)
	u.isClub = func() bool { return false }
	u.check(context.Background())
	if len(*launched) != 1 || !u.snapshot().Managed || u.snapshot().State != "INSTALLING" {
		t.Fatal("code-activated managed PC was excluded", u.snapshot())
	}
	if err := u.install(120); err == nil {
		t.Fatal("owner IPC bypassed managed policy")
	}
}

func TestManagedUpdaterCancellationNoLaunch(t *testing.T) {
	u, launched := managedUpdaterFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u.check(ctx)
	if len(*launched) != 0 {
		t.Fatal("cancelled check launched")
	}
}

func TestManagedUpdaterRechecksPolicyAndBytesAfterPreparation(t *testing.T) {
	u, launched := managedUpdaterFixture(t)
	u.isClub = func() bool { return false }
	u.managedPolicy = func() (bool, error) { return false, nil }
	u.check(context.Background())
	u.isClub = func() bool { return true }
	u.managedPolicy = func() (bool, error) { return true, nil }
	if err := os.WriteFile(u.readyPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	u.op.Lock()
	err := u.installManagedLocked()
	u.op.Unlock()
	if err == nil || len(*launched) != 0 || u.snapshot().Error != "UPDATE_DOWNLOAD_MISMATCH" {
		t.Fatal(u.snapshot(), err)
	}
}

func TestManagedUpdaterRejectsBadSignatureAndDeveloper(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	u, launched := newTestUpdater(t, updateFixture(t, 120, other, []byte("MZ evil")), pub, "100")
	u.isClub = func() bool { return true }
	u.managedPolicy = func() (bool, error) { return true, nil }
	u.check(context.Background())
	if len(*launched) != 0 || u.snapshot().Error != "UPDATE_SIGNATURE_INVALID" {
		t.Fatal(u.snapshot())
	}
	u.current = 0
	u.check(context.Background())
	if u.snapshot().Error != "DEVELOPER_BUILD" {
		t.Fatal(u.snapshot())
	}
}

func TestManagedUpdaterClaimErrorCannotLaunch(t *testing.T) {
	u, launched := managedUpdaterFixture(t)
	u.isClub = func() bool { return false }
	u.managedPolicy = func() (bool, error) { return false, nil }
	u.check(context.Background())
	u.isClub = func() bool { return true }
	u.managedPolicy = func() (bool, error) { return true, nil }
	claim := filepath.Join(u.dir, "updates", "auto-install-120.attempt")
	if err := os.Mkdir(claim, 0700); err != nil {
		t.Fatal(err)
	}
	u.op.Lock()
	err := u.installManagedLocked()
	u.op.Unlock()
	if err == nil || len(*launched) != 0 {
		t.Fatal("invalid claim launched")
	}
}

func TestManagedDownloadPacingCancellationAndChunkBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &pacedUpdateReader{ctx: ctx, reader: strings.NewReader("x"), started: time.Now().Add(time.Hour), bytes: managedUpdateBurst + 1}
	done := make(chan error, 1)
	go func() { _, err := r.Read(make([]byte, 64<<10)); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pacing ignored cancellation")
	}
	r = &pacedUpdateReader{ctx: context.Background(), reader: bytes.NewReader(make([]byte, 128<<10)), started: time.Now()}
	n, err := r.Read(make([]byte, 128<<10))
	if n != 32<<10 || err != nil {
		t.Fatal(n, err)
	}
}
