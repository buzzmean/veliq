package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
)

type readinessSession struct {
	done                 chan struct{}
	calls, closes, sends int
	destination          netip.AddrPort
	failure              error
	duringOpen           func()
}

func (s *readinessSession) Done() <-chan struct{} { return s.done }
func (s *readinessSession) OpenDatagram(ctx context.Context, dst netip.AddrPort) (routing.Datagram, error) {
	s.calls++
	s.destination = dst
	if s.duringOpen != nil {
		s.duringOpen()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if s.failure != nil {
		return nil, s.failure
	}
	return readinessDatagram{s}, nil
}

type readinessDatagram struct{ s *readinessSession }

func (d readinessDatagram) Send([]byte) error { d.s.sends++; return nil }
func (d readinessDatagram) Receive(context.Context) ([]byte, error) {
	return nil, errors.New("readiness must not receive")
}
func (d readinessDatagram) Close() error { d.s.closes++; return nil }
func readinessFixture(t *testing.T) (*Controller, *readinessSession) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	s := &readinessSession{done: make(chan struct{})}
	c.acceptanceRelays["VPS-01"] = acceptanceRelaySource{session: s, target: netip.MustParseAddrPort("203.0.113.1:40000"), generation: 1}
	return c, s
}
func TestReadinessOpensConfiguredSessionIndependentlyOfQuality(t *testing.T) {
	c, s := readinessFixture(t)
	c.Selector.ReportProbeFailure("VPS-01", "probe_loss", time.Now())
	value, err := c.Handle(context.Background(), "acceptance.readiness", json.RawMessage(`{"relay_id":"VPS-01"}`))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := value.(Snapshot)
	if snapshot.RelayTransport == nil || !snapshot.RelayTransport.Connected || !snapshot.RelayTransport.FlowOpen || snapshot.RelayTransport.CheckedAt.IsZero() {
		t.Fatal(snapshot.RelayTransport)
	}
	if s.calls != 1 || s.closes != 1 || s.sends != 0 || s.destination != c.acceptanceRelays["VPS-01"].target {
		t.Fatal("not a configured open/close-only check", s)
	}
	if c.Selector.Qualities(time.Now())["VPS-01"].Health != "unhealthy" || c.Selector.Select(time.Now()).Primary != optimizer.Direct {
		t.Fatal("readiness invented quality or selected a winner")
	}
	if c.Snapshot().RelayTransport != nil {
		t.Fatal("ordinary status invented open evidence")
	}
}
func TestReadinessUnavailableFailedClosedAndReplacedSessions(t *testing.T) {
	for _, kind := range []string{"unknown", "failed", "closed", "replaced", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			c, s := readinessFixture(t)
			id := "VPS-01"
			ctx := context.Background()
			switch kind {
			case "unknown":
				id = "unknown"
			case "failed":
				s.failure = errors.New("relay rejected flow")
			case "closed":
				close(s.done)
			case "replaced":
				s.duringOpen = func() {
					c.mu.Lock()
					source := c.acceptanceRelays[id]
					source.generation++
					c.acceptanceRelays[id] = source
					c.mu.Unlock()
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			evidence := c.acceptanceReadiness(ctx, id).RelayTransport
			if evidence.FlowOpen || evidence.Reason == "" {
				t.Fatal("invented availability", evidence)
			}
			if (kind == "unknown" || kind == "closed") && s.calls != 0 {
				t.Fatal("opened unavailable session")
			}
		})
	}
}
func TestReadinessPayloadCannotSelectArbitraryDestination(t *testing.T) {
	c, s := readinessFixture(t)
	for _, raw := range []string{`{}`, `{"relay_id":"VPS-01","target":"8.8.8.8:53"}`} {
		if _, err := c.Handle(context.Background(), "acceptance.readiness", json.RawMessage(raw)); err == nil {
			t.Fatal("invalid query accepted")
		}
	}
	if s.calls != 0 {
		t.Fatal("invalid request opened a flow")
	}
}
