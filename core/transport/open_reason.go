package transport

import (
	"context"
	"errors"
	"github.com/quic-go/quic-go"
	"io"
	"net"
)

func openIOReason(err error, end string) string {
	if reason := AuthorizationEndReason(err); reason != "" {
		return reason
	}
	var typed *OpenError
	if errors.As(err, &typed) {
		return typed.Reason
	}
	if end != "" {
		return end
	}
	if errors.Is(err, ErrCapacity) {
		return "stream_capacity"
	}
	if errors.Is(err, context.Canceled) {
		return "caller_cancelled"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "open_ack_timeout"
	}
	var stream *quic.StreamError
	if errors.As(err, &stream) {
		return "open_stream_reset"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "open_ack_eof"
	}
	return "open_io_failed"
}
