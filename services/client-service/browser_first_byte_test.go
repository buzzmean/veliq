package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"testing"
)

func TestBrowserFirstByteIPCCannotEvictRoutingEvidenceOrCreateLanes(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	for _, method := range []string{"browser.first-byte", "edge.first-byte"} {
		reply, err := c.Handle(context.Background(), method, nil)
		if err != nil {
			t.Fatal(method, err)
		}
		report := reply.(browserproxy.FirstByteReport)
		if len(report.Metrics) != 0 || report.Lost != 0 || report.Truncated {
			t.Fatal(report)
		}
	}
	if c.browser.edge != nil || c.browser.server != nil {
		t.Fatal("read-only IPC created a lane")
	}
	view := browserStatusView{Snapshot: browserproxy.Snapshot{Records: []browserproxy.Record{{ID: 1, Domain: "www.youtube.com"}}, FirstByteMetrics: make([]browserproxy.FirstByteMetric, 128)}}
	view.bound()
	raw, err := json.Marshal(view)
	if err != nil || len(raw) > 57000 || view.Truncated || len(view.Records) != 1 || view.Records[0].ID != 1 {
		t.Fatal("optional timing evicted routing evidence", len(raw), view)
	}
	var wire map[string]json.RawMessage
	json.Unmarshal(raw, &wire)
	if _, present := wire["first_byte_metrics"]; present {
		t.Fatal("timing duplicated into status")
	}
}
