package transport

import (
	"context"
	"errors"
	"github.com/buzzmean/veliq/core/protocol"
	"github.com/quic-go/quic-go"
	"io"
	"os"
	"testing"
)

func TestPreciseOpenFailures(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{os.ErrDeadlineExceeded, "open_ack_timeout"},
		{context.Canceled, "caller_cancelled"},
		{errors.Join(context.DeadlineExceeded, &quic.StreamError{ErrorCode: 1}), "open_timeout"},
		{errors.Join(context.Canceled, &quic.StreamError{ErrorCode: 1}), "caller_cancelled"},
		{io.EOF, "open_ack_eof"},
		{&quic.StreamError{ErrorCode: 1}, "open_stream_reset"},
		{&quic.ApplicationError{ErrorCode: protocol.LeaseExpiredCode}, "authorization_lease_expired"},
		{&quic.ApplicationError{ErrorCode: protocol.RevokedCode}, "device_revoked"},
		{&OpenError{Reason: "upstream_dial_timeout", Cause: ErrRelayRejected}, "upstream_dial_timeout"},
	} {
		if got := FailureReason(tc.err); got != tc.reason {
			t.Errorf("%v: got %s want %s", tc.err, got, tc.reason)
		}
	}
	if reason := openIOReason(errors.Join(context.DeadlineExceeded, &quic.StreamError{ErrorCode: 1}), ""); reason != "open_ack_timeout" {
		t.Fatal("OPEN ACK phase lost deadline cause", reason)
	}
	if !errors.Is(&OpenError{Reason: "relay_flow_capacity", Cause: ErrRelayRejected}, ErrRelayRejected) {
		t.Fatal("rejection cause lost")
	}
}
