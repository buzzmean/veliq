package clientservice

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/controlclient"
)

type subscriptionFixture struct {
	answers chan controlclient.SubscriptionStatus
	err     error
}

func (f *subscriptionFixture) SubscriptionStatus(context.Context) (controlclient.SubscriptionStatus, error) {
	if f.err != nil {
		return controlclient.SubscriptionStatus{}, f.err
	}
	return <-f.answers, nil
}

func subscriptionController(t *testing.T) (*Controller, *activationCaptureFixture) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	b := &activationCaptureFixture{}
	c.Backend = b
	// Owner SID is left empty: publishBrowserGuard would ACL the guard file with
	// it, and a fake SID fails StringToSid on Windows. These tests do not exercise
	// owner-bound policy, matching portable/demo controllers.
	if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
		t.Fatal(err)
	}
	c.Start()
	return c, b
}

func TestEndedSubscriptionSuspendsReversiblyAndResumes(t *testing.T) {
	c, b := subscriptionController(t)
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(-96 * time.Hour)
	c.applySubscription(controlclient.SubscriptionStatus{Managed: true, Enforced: true, Active: false, PaidUntil: &until}, time.Now())
	if b.active.Load() || c.activationNetworkAllowed() || c.subscriptionStatus().State != "EXPIRED" {
		t.Fatal("ended subscription kept optimizing")
	}
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err == nil || err.Error() != "ACTIVATION_REQUIRED" {
		t.Fatal("user re-enabled an ended subscription", err)
	}
	// Activation itself is untouched: no revocation state.
	if c.activationStatus().Error == "DEVICE_REVOKED" {
		t.Fatal("subscription end must not look like a revoked device")
	}
	paid := time.Now().Add(30 * 24 * time.Hour)
	c.applySubscription(controlclient.SubscriptionStatus{Managed: true, Enforced: true, Active: true, PaidUntil: &paid}, time.Now())
	if !b.active.Load() || !c.activationNetworkAllowed() || c.subscriptionStatus().State != "ACTIVE" {
		t.Fatal("payment did not resume optimization automatically")
	}
}

func TestSubscriptionUnmanagedAndNotEnforcedNeverSuspend(t *testing.T) {
	c, b := subscriptionController(t)
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	c.applySubscription(controlclient.SubscriptionStatus{Managed: false, Active: true}, time.Now())
	if c.subscriptionStatus().State != "UNMANAGED" {
		t.Fatal(c.subscriptionStatus())
	}
	past := time.Now().Add(-96 * time.Hour)
	c.applySubscription(controlclient.SubscriptionStatus{Managed: true, Enforced: false, Active: true, PaidUntil: &past}, time.Now())
	if !b.active.Load() || c.subscription.suspended.Load() {
		t.Fatal("not enforced must not suspend")
	}
}

func TestSubscriptionNetworkFailureIsNotExpiry(t *testing.T) {
	c, b := subscriptionController(t)
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.runSubscription(ctx, &subscriptionFixture{err: errors.New("control plane request failed")}); close(done) }()
	c.subscriptionRecheck()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if !b.active.Load() || c.subscription.suspended.Load() || c.subscriptionStatus().State != "UNKNOWN" {
		t.Fatal("network failure suspended the computer")
	}
	if v, err := c.Handle(context.Background(), "subscription.status", nil); err != nil || v.(SubscriptionView).State != "UNKNOWN" {
		t.Fatal("IPC subscription.status not dispatched", v, err)
	}
	if !clubReadMethod("subscription.status") {
		t.Fatal("club GUI must read subscription status")
	}
}
