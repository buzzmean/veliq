package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/enrollment"
)

func TestPersonalTrialEndsWithControlPlaneOffline(t *testing.T) {
	c, capture := subscriptionController(t)
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	c.applySubscription(controlclient.SubscriptionStatus{Managed: true, Enforced: true, Active: true, GraceUntil: &deadline}, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runSubscription(ctx, &subscriptionFixture{err: errors.New("control plane not reachable")}, nil)
	}()
	defer func() { cancel(); <-done }()
	if !c.activationNetworkAllowed() {
		t.Fatal("trial ended before the cutoff")
	}
	timeout := time.After(3 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for capture.active.Load() {
		select {
		case <-tick.C:
		case <-timeout:
			t.Fatal("trial capture continued while control plane was offline")
		}
	}
	if c.activationNetworkAllowed() || c.subscriptionStatus().State != "EXPIRED" {
		t.Fatal("new optimization remained permitted past the trial")
	}
}

func TestPersonalTrialStoredDeadlineBlocksOfflineStartup(t *testing.T) {
	c, _ := subscriptionController(t)
	stored := time.Now().Add(-time.Second)
	c.subscription.trialUntil.Store(&stored)
	if c.activationNetworkAllowed() {
		t.Fatal("expired stored trial allowed optimization before a server response")
	}
	paid := time.Now().Add(30 * 24 * time.Hour)
	c.applySubscription(controlclient.SubscriptionStatus{Managed: true, Enforced: true, Active: true, PaidUntil: &paid}, time.Now())
	if !c.activationNetworkAllowed() {
		t.Fatal("paid access did not clear the earlier trial deadline")
	}
}

func TestPersonalTrialPaymentSavesOfflineAccessForTheSameBinding(t *testing.T) {
	c, _ := subscriptionController(t)
	m := Manifest{ActivationCodeFile: filepath.Join(t.TempDir(), "activation-code.json")}
	stored := time.Now().Add(-time.Second)
	record := activationRecord{
		RequestID: strings.Repeat("a", 32), AccountOrigin: "https://cabinet.test",
		Account: enrollment.AccountBinding{Kind: "player", Subscription: strings.Repeat("b", 32), TrialUntil: &stored},
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = protectedActivationWrite(activationFile(m), raw); err != nil {
		t.Fatal(err)
	}
	if !c.rememberPaidTrial(m, strings.Repeat("d", 32)) {
		t.Fatal("old watcher could not ignore a replaced binding")
	}
	preserved, err := readActivationRecord(activationFile(m))
	if err != nil || preserved.Account.TrialUntil == nil {
		t.Fatal("confirmation for the old binding cleared the current record", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	paid := time.Now().Add(30 * 24 * time.Hour)
	answers := make(chan controlclient.SubscriptionStatus, 1)
	answers <- controlclient.SubscriptionStatus{Managed: true, Enforced: true, Active: true, PaidUntil: &paid}
	persisted := make(chan bool, 1)
	go func() {
		defer close(done)
		c.runSubscription(ctx, &subscriptionFixture{answers: answers}, func() bool {
			ok := c.rememberPaidTrial(m, record.RequestID)
			persisted <- ok
			return ok
		})
	}()
	select {
	case ok := <-persisted:
		if !ok {
			t.Fatal("confirmed paid state was not stored")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("confirmation was not applied")
	}
	updated, err := readActivationRecord(activationFile(m))
	if err != nil || updated.Account.TrialUntil != nil || updated.Account.Subscription != record.Account.Subscription {
		t.Fatal("payment did not preserve the right binding for offline startup", err)
	}
}
