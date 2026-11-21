package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"
)

// LeaseALPN negotiates bounded authenticated QUIC DATAGRAM lease control.
// Legacy /2 peers remain supported but cannot renew an established session.
const LeaseALPN = "neexitlag/3"
const LeaseExpiredCode = 10
const RevokedCode = 11
const ClientLeaseExpiredCode = 12

type LeaseAck struct {
	Status   byte
	Sequence uint64
	Deadline time.Time
	Duration time.Duration
}

func WriteLeaseAck(w io.Writer, a LeaseAck) error {
	var b [25]byte
	b[0] = a.Status
	binary.BigEndian.PutUint64(b[1:9], a.Sequence)
	binary.BigEndian.PutUint64(b[9:17], uint64(a.Deadline.UnixNano()))
	binary.BigEndian.PutUint64(b[17:25], uint64(a.Duration))
	_, err := w.Write(b[:])
	return err
}
func ReadLeaseAck(r io.Reader) (LeaseAck, error) {
	var b [25]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return LeaseAck{}, err
	}
	return LeaseAck{b[0], binary.BigEndian.Uint64(b[1:9]), time.Unix(0, int64(binary.BigEndian.Uint64(b[9:17]))), time.Duration(binary.BigEndian.Uint64(b[17:25]))}, nil
}
func WriteRenewal(w io.Writer, seq uint64, ticket []byte) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	if _, err := w.Write(b[:]); err != nil {
		return err
	}
	return WriteTicket(w, ticket)
}
func ReadRenewal(r io.Reader) (uint64, []byte, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, nil, err
	}
	t, err := ReadTicket(r)
	return binary.BigEndian.Uint64(b[:]), t, err
}

// Control DATAGRAMs bypass application-stream/connection receive credit. Their
// own reassembly is one bounded message, separate from application UDP tables.
const LeaseRequestDatagram byte = 0xa3
const LeaseAckDatagram byte = 0xa4
const leaseChunk = 1024
const maxLeaseChunks = 9

func LeaseRequests(seq uint64, ticket []byte) ([][]byte, error) {
	var message bytes.Buffer
	if err := WriteRenewal(&message, seq, ticket); err != nil {
		return nil, err
	}
	data := message.Bytes()
	count := (len(data) + leaseChunk - 1) / leaseChunk
	frames := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 11+min(leaseChunk, len(data)-i*leaseChunk))
		b[0] = LeaseRequestDatagram
		binary.BigEndian.PutUint64(b[1:9], seq)
		b[9] = byte(i)
		b[10] = byte(count)
		copy(b[11:], data[i*leaseChunk:])
		frames = append(frames, b)
	}
	return frames, nil
}

type LeaseAssembly struct {
	sequence uint64
	parts    [maxLeaseChunks][]byte
	count    int
	started  time.Time
}

func (a *LeaseAssembly) Add(b []byte, now time.Time) ([]byte, error) {
	if len(b) < 12 || len(b) > 11+leaseChunk || b[0] != LeaseRequestDatagram || b[10] == 0 || b[10] > maxLeaseChunks || b[9] >= b[10] {
		return nil, ErrFrame
	}
	seq := binary.BigEndian.Uint64(b[1:9])
	if seq == 0 {
		return nil, ErrFrame
	}
	if a.started.IsZero() || seq != a.sequence || now.Sub(a.started) > 3*time.Second {
		*a = LeaseAssembly{sequence: seq, count: int(b[10]), started: now}
	}
	if a.count != int(b[10]) {
		return nil, ErrFrame
	}
	a.parts[b[9]] = append([]byte(nil), b[11:]...)
	var data []byte
	for i := 0; i < a.count; i++ {
		if a.parts[i] == nil {
			return nil, nil
		}
	}
	for i := 0; i < a.count; i++ {
		data = append(data, a.parts[i]...)
	}
	sequence := a.sequence
	*a = LeaseAssembly{}
	if len(data) < 12 || binary.BigEndian.Uint64(data[:8]) != sequence {
		return nil, ErrFrame
	}
	if len(data) > MaxTicket+12 {
		return nil, ErrFrame
	}
	return data, nil
}
func LeaseAckFrame(ack LeaseAck) []byte {
	var b bytes.Buffer
	b.WriteByte(LeaseAckDatagram)
	_ = WriteLeaseAck(&b, ack)
	return b.Bytes()
}
func ParseLeaseAckFrame(b []byte) (LeaseAck, error) {
	if len(b) != 26 || b[0] != LeaseAckDatagram {
		return LeaseAck{}, ErrFrame
	}
	return ReadLeaseAck(bytes.NewReader(b[1:]))
}
