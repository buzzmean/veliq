package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/optimizer"
	windowsplatform "github.com/buzzmean/veliq/platform/windows"
	"net/netip"
	"testing"
	"time"
)

type scopedTestBackend struct {
	ledger *windowsplatform.EvidenceLedger
}

func (*scopedTestBackend) Start(context.Context, windowsplatform.Classifier) error { return nil }
func (*scopedTestBackend) Stop() error                                             { return nil }
func (*scopedTestBackend) Status() windowsplatform.CaptureStatus {
	return windowsplatform.CaptureStatus{}
}
func (b *scopedTestBackend) CaptureMarker() windowsplatform.EvidenceMarker { return b.ledger.Marker() }
func (b *scopedTestBackend) DiagnosticsScoped(q windowsplatform.EvidenceQuery) (windowsplatform.CaptureEvidence, error) {
	return b.ledger.SnapshotQuery(q, nil)
}
func TestCaptureScopeIPCIsStrictAndBackwardCompatible(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	l := windowsplatform.NewEvidenceLedger()
	c.Backend = &scopedTestBackend{l}
	marker, err := c.Handle(context.Background(), "capture.marker", nil)
	if err != nil {
		t.Fatal(err)
	}
	m := marker.(windowsplatform.EvidenceMarker)
	id := windowsplatform.ProcessIdentity{PID: 42, CreationTime: 10, Path: "chrome.exe"}
	tuple := windowsplatform.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	l.BeginFlow(id, tuple)
	l.RecordBytes(id, tuple, "relay", "VPS-01", 10655)
	q := windowsplatform.EvidenceQuery{PID: 42, CreationTime: 10, Destination: tuple.Destination.String(), Since: &m}
	raw, _ := json.Marshal(q)
	out, err := c.Handle(context.Background(), "capture.diagnostics", raw)
	if err != nil || len(out.(windowsplatform.CaptureEvidence).Flows) != 1 {
		t.Fatal(out, err)
	}
	q.CreationTime++
	raw, _ = json.Marshal(q)
	out, err = c.Handle(context.Background(), "capture.diagnostics", raw)
	if err != nil || len(out.(windowsplatform.CaptureEvidence).Flows) != 0 {
		t.Fatal("PID reuse", out, err)
	}
	for _, raw := range []string{`{"creation_time":10}`, `{"pid":42,"source":"invalid"}`, `{"pid":42,"domain":"host/path"}`, `{"pid":42,"since":{"ledger_id":"stale","after_flow_id":0,"lost_records":0}}`} {
		if _, err := c.Handle(context.Background(), "capture.diagnostics", json.RawMessage(raw)); err == nil {
			t.Fatal("invalid scope accepted", raw)
		}
	}
}

func (b *scopedTestBackend) DiagnosticsTarget(pid uint32, destination string) windowsplatform.CaptureEvidence {
	v, _ := b.ledger.SnapshotQuery(windowsplatform.EvidenceQuery{PID: pid, Destination: destination}, nil)
	return v
}
func TestSuccessfulChainRecordUsesExactTrialFlow(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	l := windowsplatform.NewEvidenceLedger()
	c.Backend = &scopedTestBackend{l}
	app := `C:\Apps\chrome.exe`
	config, strategy, err := localstrategy.PresetProfiles("youtube", app, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: config}); err != nil {
		t.Fatal(err)
	}
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "net", ObservedAt: time.Now()})
	id := windowsplatform.ProcessIdentity{PID: 42, CreationTime: 10, Path: app}
	tuple := windowsplatform.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:55000"), Destination: netip.MustParseAddrPort("203.0.113.9:443")}
	// Stale same-PID/destination evidence cannot truncate the scoped commit proof.
	for i := 0; i < 40; i++ {
		old := tuple
		old.Source = netip.AddrPortFrom(old.Source.Addr(), uint16(3000+i))
		l.Record(id, old, "direct", "")
	}
	marker := l.Marker()
	l.BeginFlow(id, tuple)
	l.RecordBytes(id, tuple, "captured", "", 100)
	l.RecordLocalResult(id, tuple, localstrategy.Result{Strategy: strategy, Domain: "www.youtube.com", Revision: c.Local.Revision()}, 100)
	l.RecordLocalInspection(id, tuple, &localstrategy.Inspection{Reason: "REASSEMBLY_COMPLETE", TransformApplied: true, Domain: "www.youtube.com"})
	ev, _ := l.SnapshotQuery(windowsplatform.EvidenceQuery{PID: 42, CreationTime: 10, Destination: tuple.Destination.String(), Since: &marker}, nil)
	request := localRecord{Application: app, PID: 42, CreationTime: 10, Destination: tuple.Destination.String(), Source: tuple.Source.String(), Domain: "www.youtube.com", FlowID: ev.Flows[0].FlowID, CaptureMarker: &marker, Protocol: "tcp", Network: "net", Strategy: strategy, Success: true, Measurement: optimizer.RouteMeasurement{RouteID: "target", Available: true, Samples: 1, RTT: time.Millisecond, Stability: 1, ObservedAt: time.Now()}}
	raw, _ := json.Marshal(request)
	if _, err = c.Handle(context.Background(), "local.record", raw); err != nil {
		t.Fatal("scoped proof lost to stale frame truncation", err)
	}
	request.FlowID--
	raw, _ = json.Marshal(request)
	if _, err = c.Handle(context.Background(), "local.record", raw); err == nil {
		t.Fatal("wrong flow generation accepted")
	}
}

func (b *scopedTestBackend) CaptureChangeMarker() windowsplatform.ChangeCursor {
	return b.ledger.ChangeMarker()
}
func (b *scopedTestBackend) CaptureChanges(q windowsplatform.ChangeQuery) (windowsplatform.ChangePage, error) {
	return b.ledger.ChangePage(q)
}
func TestCaptureChangesIPCIsBoundedAndStrict(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	l := windowsplatform.NewEvidenceLedger()
	c.Backend = &scopedTestBackend{l}
	cursor, err := c.Handle(context.Background(), "capture.changes.marker", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(windowsplatform.ChangeQuery{Cursor: cursor.(windowsplatform.ChangeCursor)})
	if _, err = c.Handle(context.Background(), "capture.changes", raw); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Handle(context.Background(), "capture.changes", json.RawMessage(`{"cursor":{"ledger_id":"foreign","after_update":0}}`)); err == nil {
		t.Fatal("foreign cursor accepted")
	}
	if _, err = c.Handle(context.Background(), "capture.changes", json.RawMessage(`{"cursor":{},"unknown":1}`)); err == nil {
		t.Fatal("unknown request field accepted")
	}
}
