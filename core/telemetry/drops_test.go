package telemetry

import (
	"errors"
	"testing"
)

func TestInternalQueueDropClassification(t *testing.T) {
	var counters Counters
	queue := make(chan []byte, 1)
	if !counters.TryEnqueue(queue, []byte{1}, TransportQueue) || counters.TryEnqueue(queue, []byte{2}, TransportQueue) {
		t.Fatal("queue outcome")
	}
	snapshot := counters.Snapshot()
	if snapshot["transport_queue_drops"].Count != 1 || snapshot["transport_queue_drops"].Attempts != 2 || *snapshot["transport_queue_drops"].Fraction != .5 || snapshot["relay_socket_send_drops"].Count != 0 {
		t.Fatal(snapshot)
	}
	if snapshot["capture_queue_drops"].Fraction != nil {
		t.Fatal("invented denominator")
	}
}
func TestLocalErrorPreservesCause(t *testing.T) {
	cause := errors.New("full")
	wrapped := &LocalError{TransportQueue, cause}
	if !IsLocal(wrapped) || !errors.Is(wrapped, cause) || IsLocal(cause) {
		t.Fatal("local error mapping")
	}
}
