package clientservice

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

func browserQUICKey() browserproxy.HTTP3ProbeKey {
	return browserproxy.HTTP3ProbeKey{Host: "www.youtube.com", Endpoint: netip.MustParseAddrPort("74.125.111.131:443"), PID: 1, Birth: 2, Executable: `C:\Fixture\chrome.exe`, Network: "net", Profile: "chrome", Revision: "revision"}
}
func TestBrowserQUICProbeBudgetClaimAndClose(t *testing.T) {
	r := newBrowserQUICRuntime()
	defer r.close()
	slots := make(chan struct{}, 4)
	ctx := context.Background()
	k := browserQUICKey()
	now := time.Now()
	claims := 0
	claim := func() bool { claims++; return true }
	current := func(browserproxy.HTTP3ProbeKey) bool { return true }
	opened := make(chan struct{})
	open := func(ctx context.Context) (browserproxy.HTTP3ProbeSocket, error) {
		close(opened)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	for _, host := range []string{"api.openai.com", "example.com", "localhost"} {
		bad := k
		bad.Host = host
		if r.submit(ctx, bad, claim, current, open, nil, slots, now) {
			t.Fatal("non-DPI admitted")
		}
	}
	for i := 0; i < 4; i++ {
		slots <- struct{}{}
	}
	if r.submit(ctx, k, claim, current, open, nil, slots, now) || claims != 0 {
		t.Fatal("shared budget escaped")
	}
	<-slots
	if r.submit(ctx, k, func() bool { return false }, current, open, nil, slots, now) || len(slots) != 3 {
		t.Fatal("failed claim leaked budget")
	}
	if !r.submit(ctx, k, claim, current, open, nil, slots, now) {
		t.Fatal("fresh claim not scheduled")
	}
	select {
	case <-opened:
	case <-time.After(time.Second):
		t.Fatal("worker did not open")
	}
	if r.submit(ctx, k, claim, current, open, nil, slots, now.Add(time.Minute)) || claims != 1 {
		t.Fatal("active worker queued/retried")
	}
	r.close()
	s := r.snapshot()
	if len(slots) != 3 || s["active"] != false || s["attempts"] != uint64(1) || s["canceled"] != uint64(1) || s["observed"] != uint64(0) || len(r.retry) != 0 {
		t.Fatal("close/budget/neutral cancellation", s)
	}
	if r.submit(ctx, k, claim, current, open, nil, slots, now.Add(time.Hour)) {
		t.Fatal("closed runtime reopened")
	}
}
func TestBrowserQUICProbeCooldownStaleScopeAndBoundedHistory(t *testing.T) {
	r := newBrowserQUICRuntime()
	defer r.close()
	slots := make(chan struct{}, 4)
	now := time.Now()
	ctx := context.Background()
	k := browserQUICKey()
	claims := 0
	claim := func() bool { claims++; return true }
	opens := 0
	open := func(context.Context) (browserproxy.HTTP3ProbeSocket, error) {
		opens++
		return nil, errors.New("isolated failure")
	}
	stale := func(browserproxy.HTTP3ProbeKey) bool { return false }
	current := func(browserproxy.HTTP3ProbeKey) bool { return true }
	if !r.submit(ctx, k, claim, stale, open, nil, slots, now) {
		t.Fatal("stale test not queued")
	}
	r.workers.Wait()
	if opens != 0 || len(r.retry) != 0 || r.snapshot()["canceled"] != uint64(1) {
		t.Fatal("stale scope opened or cached")
	}
	if r.submit(ctx, k, claim, current, open, nil, slots, now.Add(time.Second)) {
		t.Fatal("global rate limit escaped")
	}
	if !r.submit(ctx, k, claim, current, open, nil, slots, now.Add(31*time.Second)) {
		t.Fatal("next fresh trigger refused")
	}
	r.workers.Wait()
	if opens != 1 || r.submit(ctx, k, claim, current, open, nil, slots, now.Add(62*time.Second)) {
		t.Fatal("same-scope cooldown escaped")
	}
	for i := 0; i < 18; i++ {
		next := k
		next.Revision = fmt.Sprint(i)
		if !r.submit(ctx, next, claim, current, open, nil, slots, now.Add(time.Duration(200+i*31)*time.Second)) {
			t.Fatal("fresh distinct scope refused")
		}
		r.workers.Wait()
	}
	s := r.snapshot()
	records := s["records"].([]browserQUICRecord)
	if len(records) != 16 || s["observed"] != uint64(0) || len(slots) != 0 {
		t.Fatal("history/budget escaped", s)
	}
	records[0].Host = "mutated"
	if r.snapshot()["records"].([]browserQUICRecord)[0].Host == "mutated" {
		t.Fatal("snapshot alias")
	}
	r.mu.Lock()
	r.retry = make(map[browserproxy.HTTP3ProbeKey]time.Time)
	for i := 0; i < 128; i++ {
		v := k
		v.Revision = fmt.Sprint(i)
		r.retry[v] = now.Add(time.Hour)
	}
	r.mu.Unlock()
	if r.submit(ctx, k, claim, current, open, nil, slots, now.Add(20*time.Minute)) {
		t.Fatal("cooldown capacity escaped")
	}
}
