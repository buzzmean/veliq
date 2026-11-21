package clientservice

import (
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"testing"
)

func TestLayerAuditIsPassiveAndDistinguishesUnknownTimestamp(t *testing.T) {
	a := localLayerAudit{}
	i := &localstrategy.Inspection{TimestampOption: true, TCPPackets: localstrategy.TCPTrace{ClientEarlyRetransmits: 3, RemoteRST: 1, RemoteRSTRelativeKnown: true, RemoteRSTRelative: 20}}
	actions := []localstrategy.Action{{Native: &localstrategy.NativeTCPPlan{Fooling: "ts"}}}
	auditLayerFlow(&a, actions, i, "MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED", 17000)
	if a.PureTS != 1 || a.PureTSMissingPayloadTimestamp != 0 || a.PureTSNegotiationUnknown != 1 || a.PureTSNotNegotiated != 0 || a.EarlyRetransmitCandidates != 1 || a.SmallRSTCandidates != 1 || a.Freeze16To20KiB != 1 || a.LateFailuresAfterReply != 1 {
		t.Fatal(a)
	}
	auditLayerFlow(&a, []localstrategy.Action{{Fooling: "ts,md5sig"}}, &localstrategy.Inspection{Reason: "TIMESTAMP_OPTION_REQUIRED"}, "", 0)
	if a.PureTS != 1 || a.TimestampOptionRequired != 1 {
		t.Fatal(a)
	}
}
