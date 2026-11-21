package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestLeaseControlBoundedReassembly(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, MaxTicket)
	frames, err := LeaseRequests(17, raw)
	if err != nil || len(frames) != 9 {
		t.Fatal(len(frames), err)
	}
	var assembly LeaseAssembly
	var message []byte
	for i := len(frames) - 1; i >= 0; i-- {
		if len(frames[i]) > 1035 {
			t.Fatal("unbounded control datagram")
		}
		message, err = assembly.Add(frames[i], time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	seq, got, err := ReadRenewal(bytes.NewReader(message))
	if err != nil || seq != 17 || !bytes.Equal(raw, got) {
		t.Fatal(seq, len(got), err)
	}
	if _, err = assembly.Add(make([]byte, 1036), time.Now()); err == nil {
		t.Fatal("oversized control accepted")
	}
	if _, err = LeaseRequests(1, append(raw, 1)); err == nil {
		t.Fatal("oversized ticket accepted")
	}
	short := make([]byte, 12)
	short[0] = LeaseRequestDatagram
	short[8] = 1
	short[10] = 1
	if _, err = assembly.Add(short, time.Now()); err == nil {
		t.Fatal("short assembled control accepted")
	}
	ack := LeaseAck{Sequence: 17, Deadline: time.Now(), Duration: time.Minute}
	gotAck, err := ParseLeaseAckFrame(LeaseAckFrame(ack))
	if err != nil || gotAck.Sequence != 17 || !gotAck.Deadline.Equal(ack.Deadline) {
		t.Fatal(gotAck, err)
	}
}

func FuzzLeaseControlAssembly(f *testing.F) {
	frames, _ := LeaseRequests(1, []byte("ticket"))
	f.Add(frames[0])
	f.Add([]byte{LeaseRequestDatagram})
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, b []byte) {
		var a LeaseAssembly
		_, _ = a.Add(b, time.Now())
		_, _ = ParseLeaseAckFrame(b)
	})
}
