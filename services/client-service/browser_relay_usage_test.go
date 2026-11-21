package clientservice

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestVideoLimitIsPerPCAndReleasesExactlyOnceOnClose(t *testing.T) {
	u := &browserRelayUsage{minutes: map[relayMinuteKey]relayMinute{}}
	var release []func()
	for i := 0; i < videoRelayLimit; i++ {
		r, ok := u.acquireVideo()
		if !ok {
			t.Fatal("under limit rejected")
		}
		release = append(release, r)
	}
	if _, ok := u.acquireVideo(); ok {
		t.Fatal("over-limit video admitted")
	}
	release[0]()
	release[0]()
	r, ok := u.acquireVideo()
	if !ok {
		t.Fatal("permit not released")
	}
	r()
	for _, r := range release[1:] {
		r()
	}
	if s := u.snapshot(); s.VideoActive != 0 || s.VideoLimitHits != 1 {
		t.Fatal(s)
	}
}
func TestRelayMeterCountsActualActiveIOInCorrectMinuteProfileDomain(t *testing.T) {
	u := &browserRelayUsage{minutes: map[relayMinuteKey]relayMinute{}}
	a, b := net.Pipe()
	defer b.Close()
	released := 0
	c := &relayMeterConn{Conn: a, usage: u, profile: "edge", domain: "video.googlevideo.com", release: func() { released++ }}
	go func() { buf := make([]byte, 16); b.Read(buf); b.Write([]byte("response")) }()
	if n, e := c.Write([]byte("request")); e != nil || n != 7 {
		t.Fatal(n, e)
	}
	buf := make([]byte, 16)
	if n, e := c.Read(buf); e != nil || n != 8 {
		t.Fatal(n, e)
	}
	s := u.snapshot()
	if len(s.Minutes) != 1 || s.Minutes[0].Sent != 7 || s.Minutes[0].Received != 8 || s.Minutes[0].Profile != "edge" || s.Minutes[0].Domain != "video.googlevideo.com" {
		t.Fatal(s)
	}
	c.Close()
	c.Close()
	if released != 1 {
		t.Fatal("permit release repeated")
	}
	now := time.Now().UTC().Truncate(time.Minute)
	u.account("chrome", "youtube.com", 20, 30, now.Add(-time.Minute))
	u.account("chrome", "youtube.com", 50, 60, now)
	if len(u.snapshot().Minutes) != 3 {
		t.Fatal("minute/profile attribution lost")
	}
}
func TestRelayUsageIsBoundedAndReportsOverflowInsteadOfSilentlyLosingEvidence(t *testing.T) {
	u := &browserRelayUsage{minutes: map[relayMinuteKey]relayMinute{}}
	now := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				u.account("p", fmt.Sprintf("%d-%d.example", g, i), 1, 1, now)
			}
		}(g)
	}
	wg.Wait()
	if len(u.minutes) > relayUsageCapacity {
		t.Fatal("unbounded usage")
	}
	s := u.snapshot()
	if !s.Truncated || s.OverflowBytes == 0 || len(s.Minutes) > 64 {
		t.Fatal(s)
	}
	u.account("p", "new.example", 1, 1, now.Add(relayUsageRetention+time.Minute))
	if len(u.minutes) != 1 {
		t.Fatal("retention did not evict old minutes")
	}
}

func TestVideoAdmissionWaitsForSlotAndNeverExceedsDedicatedLimit(t *testing.T) {
	u := &browserRelayUsage{}
	var held []func()
	for i := 0; i < videoRelayLimit; i++ {
		r, ok := u.acquireVideo()
		if !ok {
			t.Fatal("capacity")
		}
		held = append(held, r)
	}
	result := make(chan func(), 1)
	go func() {
		r, ok := u.acquireVideoContext(context.Background())
		if !ok {
			result <- nil
			return
		}
		result <- r
	}()
	deadline := time.Now().Add(time.Second)
	for u.snapshot().VideoWaiting != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if u.snapshot().VideoWaiting != 1 {
		t.Fatal("waiter not queued")
	}
	select {
	case <-result:
		t.Fatal("ninth admitted without slot")
	default:
	}
	held[0]()
	select {
	case r := <-result:
		if r == nil {
			t.Fatal("released slot not acquired")
		}
		r()
	case <-time.After(time.Second):
		t.Fatal("waiter stuck")
	}
	for _, r := range held[1:] {
		r()
	}
	if u.snapshot().VideoActive != 0 {
		t.Fatal("permit leaked")
	}
}
func TestVideoAdmissionIsBoundedAndCanceledWaiterDoesNotLeak(t *testing.T) {
	u := &browserRelayUsage{}
	var held []func()
	for i := 0; i < videoRelayLimit; i++ {
		r, _ := u.acquireVideo()
		held = append(held, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if _, ok := u.acquireVideoContext(ctx); ok {
		t.Fatal("saturated admitted")
	}
	if s := u.snapshot(); s.VideoWaiting != 0 || s.VideoCanceled != 1 || s.VideoTimeouts != 0 || s.VideoActive != videoRelayLimit {
		t.Fatal(s)
	}
	u.mu.Lock()
	u.videoAdmission.waiting = videoRelayWaitLimit
	u.mu.Unlock()
	started := time.Now()
	if _, ok := u.acquireVideoContext(context.Background()); ok || time.Since(started) > time.Second {
		t.Fatal("unbounded queue")
	}
	for _, r := range held {
		r()
	}
}

func TestVideoAdmissionHardDeadlineLeavesEstablishedTunnelsUntouched(t *testing.T) {
	u := &browserRelayUsage{}
	for i := 0; i < videoRelayLimit; i++ {
		r, ok := u.acquireVideo()
		if !ok {
			t.Fatal("capacity")
		}
		defer r()
	}
	started := time.Now()
	if _, ok := u.acquireVideoContext(context.Background()); ok {
		t.Fatal("over hard cap")
	}
	elapsed := time.Since(started)
	if elapsed < videoRelayWait-50*time.Millisecond || elapsed > videoRelayWait+time.Second {
		t.Fatal("admission deadline", elapsed)
	}
	if s := u.snapshot(); s.VideoActive != videoRelayLimit || s.VideoWaiting != 0 || s.VideoTimeouts != 1 {
		t.Fatal("healthy tunnels disrupted or waiter leaked", s)
	}
}
