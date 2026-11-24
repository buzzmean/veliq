package measurement

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
)

// scripted answers each probe by plan: ontime, late (after Timeout), lost, senderr.
type scripted struct {
	mu    sync.Mutex
	plan  []string
	next  int
	inbox chan []byte
	delay map[string]time.Duration
}

func newScripted(plan ...string) *scripted {
	return &scripted{plan: plan, inbox: make(chan []byte, 64), delay: map[string]time.Duration{"ontime": 5 * time.Millisecond, "late": 250 * time.Millisecond}}
}
func (s *scripted) Send(p []byte) error {
	s.mu.Lock()
	kind := s.plan[s.next%len(s.plan)]
	s.next++
	s.mu.Unlock()
	if kind == "senderr" {
		return errors.New("socket send failed")
	}
	if d, ok := s.delay[kind]; ok {
		payload := append([]byte(nil), p...)
		time.AfterFunc(d, func() { s.inbox <- payload })
	}
	return nil
}
func (s *scripted) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-s.inbox:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *scripted) Close() error { return nil }

func scriptedCandidate(id string, s *scripted) Candidate {
	return Candidate{Metadata: optimizer.RelayCandidate{ID: id}, Target: netip.MustParseAddrPort("192.0.2.1:40000"),
		Open: func(context.Context, netip.AddrPort) (routing.Datagram, error) { return s, nil }}
}

func TestAccountingSeparatesLossFromDelayAndSendErrors(t *testing.T) {
	e := New(Settings{Samples: 5, Timeout: 100 * time.Millisecond, Spacing: 20 * time.Millisecond, Concurrency: 1, LateWindow: 400 * time.Millisecond})
	flow := newScripted("ontime", "late", "lost", "ontime", "senderr")
	m := e.Probe(context.Background(), scriptedCandidate("R", flow))
	// Scoring is unchanged: anything not answered within Timeout counts as loss.
	if m.Samples != 5 {
		t.Fatalf("%+v", m)
	}
	views := e.Accounts(time.Now())
	if len(views) != 1 || views[0].RouteID != "R" {
		t.Fatalf("%+v", views)
	}
	for name, w := range map[string]AccountWindow{"all": views[0].All, "last5min": views[0].Last5Min} {
		if w.Sent != 4 || w.OnTime != 2 || w.Late != 1 || w.NoReply != 1 || w.SendErrors != 1 {
			t.Fatalf("%s: %+v", name, w)
		}
		if w.LossStrictPercent != 50 || w.LossTruePercent != 25 || w.LatePercent != 25 {
			t.Fatalf("%s percents: %+v", name, w)
		}
		if w.LateRTTMaxMs < 100 || w.LateRTTMaxMs > 400 || w.LateRTTAvgMs < 100 {
			t.Fatalf("%s late RTT must be the real, post-timeout delay: %+v", name, w)
		}
	}
}

func TestLateReplyAfterLastSampleIsStillCountedWithinWindow(t *testing.T) {
	e := New(Settings{Samples: 1, Timeout: 50 * time.Millisecond, Spacing: 20 * time.Millisecond, Concurrency: 1, LateWindow: 600 * time.Millisecond})
	flow := newScripted("late")
	flow.delay["late"] = 200 * time.Millisecond
	e.Probe(context.Background(), scriptedCandidate("R", flow))
	w := e.Accounts(time.Now())[0].All
	if w.Sent != 1 || w.Late != 1 || w.NoReply != 0 {
		t.Fatalf("%+v", w)
	}
}

func TestAccountingCountsTrueLossWhenNothingEverArrives(t *testing.T) {
	e := New(Settings{Samples: 3, Timeout: 40 * time.Millisecond, Spacing: 20 * time.Millisecond, Concurrency: 1, LateWindow: 100 * time.Millisecond})
	e.Probe(context.Background(), scriptedCandidate("R", newScripted("lost")))
	w := e.Accounts(time.Now())[0].All
	if w.Sent != 3 || w.NoReply != 3 || w.Late != 0 || w.LossTruePercent != 100 || w.LossStrictPercent != 100 {
		t.Fatalf("%+v", w)
	}
}

func TestLast5MinuteWindowForgetsOldSamples(t *testing.T) {
	e := New(Settings{Samples: 2, Timeout: 40 * time.Millisecond, Spacing: 20 * time.Millisecond, Concurrency: 1, LateWindow: 50 * time.Millisecond})
	e.Probe(context.Background(), scriptedCandidate("R", newScripted("lost")))
	v := e.Accounts(time.Now().Add(6 * time.Minute))[0]
	if v.All.Sent != 2 || v.Last5Min.Sent != 0 {
		t.Fatalf("old samples leaked into the 5-minute window: %+v", v)
	}
}
