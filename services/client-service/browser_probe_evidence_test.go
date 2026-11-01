package clientservice

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"strings"
	"testing"
)

func TestLocalProbeFailuresAreNotAllNoTransform(t *testing.T) {
	for _, tc := range []struct {
		p       browserproxy.ProbeResult
		applied bool
		want    string
	}{
		{browserproxy.ProbeResult{Failure: "NETWORK_TIMEOUT"}, false, "ORIGIN_SILENT"},
		{browserproxy.ProbeResult{Detail: "PEER_RESET"}, true, "RST"},
		{browserproxy.ProbeResult{BodyBytes: 16000, Bytes: 18000, Failure: "NETWORK_TIMEOUT"}, true, "FREEZE_AFTER_N"},
		{browserproxy.ProbeResult{Status: 200, TLSVersion: 0x304, BodyBytes: 70000}, false, "NO_TRANSFORM"},
		{browserproxy.ProbeResult{Bytes: 1000, BodyBytes: 200, Failure: "WRONG_WEBSOCKET_NONCE"}, true, "ORIGIN_PROTOCOL_OR_BODY_FAILED"},
		{browserproxy.ProbeResult{Bytes: 1000, BodyBytes: 200, Failure: "NETWORK_ERROR", Detail: "PEER_CLOSED"}, true, "EOF_AFTER_N"},
		{browserproxy.ProbeResult{Status: 200, TLSVersion: 0x304, BodyBytes: 70000}, true, "OK"},
	} {
		if got := localProbeOutcome(tc.p, tc.applied); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
}

func TestLocalProbeSnapshotBoundedBelowIPC(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	for i := 0; i < 128; i++ {
		c.browser.youtube.probeEvidence = append(c.browser.youtube.probeEvidence, localProbeEvidence{Host: strings.Repeat("x", 253), Strategy: strings.Repeat("s", 96), Inspection: &localstrategy.Inspection{Detail: strings.Repeat("d", 1024), SentPackets: make([]localstrategy.SentPacket, 20)}})
	}
	for i := uint64(1); i <= 8; i++ {
		c.browser.youtube.records[i] = youtubeRecord{ID: i, Stage: "LOCAL", Domain: strings.Repeat("d", 253), Reason: "EARLY_EOF_OR_IO_NO_REPLAY", Inspection: &localstrategy.Inspection{SentPackets: make([]localstrategy.SentPacket, 64)}}
	}
	for i := uint64(1); i <= 32; i++ {
		c.browser.youtube.trials = append(c.browser.youtube.trials, cdnTrialEvidence{ID: i, Host: strings.Repeat("h", 253), Strategy: strings.Repeat("s", 96), Sibling: relaySiblingEvidence{Reason: "RECENT_CDN_CLASS", Subgroup: strings.Repeat("g", 63)}})
	}
	for i := uint64(0); i < 32; i++ {
		c.browser.youtube.ordinary = append(c.browser.youtube.ordinary, ordinaryFlowEvidence{ID: i, Host: strings.Repeat("h", 253), Profile: strings.Repeat("p", 128), Reason: strings.Repeat("r", 512), Addresses: []ordinaryAddressEvidence{{Address: "87.240.137.208:443", Stage: "DIRECT", Result: strings.Repeat("d", 512)}}})
	}
	snapshot := c.localProbeSnapshot()
	if len(snapshot["ordinary"].([]ordinaryFlowEvidence)) == 0 {
		t.Fatal("IPC trimming hid all ordinary retries as NONE_RECORDED")
	}
	raw, e := json.Marshal(snapshot)
	if e != nil || len(raw) >= 49000 {
		t.Fatal(len(raw), e)
	}
}

func TestNativeSnapshotRetainsIPCHeadroomWithSiblingCache(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	r := c.browser.youtube
	for i := 0; i < 64; i++ {
		c.browser.dnsWire.record(strings.Repeat("n", 64), strings.Repeat("p", 128), strings.Repeat("d", 253), 1, "AUTHENTICATED_RELAY_DOH", "DNS_NXDOMAIN", 0)
	}
	for i := 0; i < 128; i++ {
		label := fmt.Sprint(i)
		r.stats[label] = youtubeStage{Service: "youtube-media", Stage: "LOCAL", Strategy: strings.Repeat("s", 64) + label}
		k := youtubeKey{Network: "network", Profile: strings.Repeat("p", 128), Domain: strings.Repeat("d", 240) + label, Port: 443}
		r.cache[k] = youtubeLearn{Reason: strings.Repeat("r", 100), Sibling: relaySiblingEvidence{Reason: "RECENT_SAME_SUBGROUP", Subgroup: strings.Repeat("g", 63)}, Stage: "RELAY"}
	}
	for i := uint64(1); i <= 24; i++ {
		r.records[i] = youtubeRecord{ID: i, Profile: strings.Repeat("p", 128), Domain: strings.Repeat("d", 253), Strategy: strings.Repeat("s", 64), Reason: strings.Repeat("r", 100)}
	}
	raw, e := json.Marshal(c.nativeSnapshot())
	if e != nil || len(raw) > 60*1024 {
		t.Fatal(len(raw), e)
	}
}
