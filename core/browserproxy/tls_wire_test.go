package browserproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func TestTLSWireFragmentedHeadersAndCompleteAlert(t *testing.T) {
	var o TLSWireObserver
	// A large opaque ClientHello. Observer must skip its body, not parse extensions.
	hello := append([]byte{22, 3, 1, 8, 0, 1, 0, 7, 252}, bytes.Repeat([]byte{0x7a}, 2044)...)
	for _, b := range hello {
		o.ObserveClient([]byte{b})
	}
	alert := []byte{21, 3, 3, 0, 2, 2, 40}
	o.ObserveOrigin(alert[:5])
	s := o.Snapshot()
	if s.Client.ClientHelloBytes != 2048 || !s.Client.Records[0].Complete || s.Client.Bytes != 2053 {
		t.Fatal(s)
	}
	if s.Origin.State != "TLS_HEADER_ONLY" || s.Origin.AlertLevel != 0 || s.Origin.Records[0].Complete {
		t.Fatal(s)
	}
	o.ObserveOrigin(alert[5:6])
	if got := o.Snapshot().Origin; got.State != "TLS_RECORD_INCOMPLETE" || got.AlertLevel != 0 {
		t.Fatal(got)
	}
	o.ObserveOrigin(alert[6:])
	got := o.Snapshot().Origin
	if got.State != "TLS_PLAINTEXT_ALERT_COMPLETE" || got.AlertLevel != 2 || got.AlertDescription != 40 || got.Prefix != "15030300020228" {
		t.Fatal(got)
	}
	raw, _ := json.Marshal(o.Snapshot())
	if bytes.Contains(raw, []byte("7a7a7a")) {
		t.Fatal("ClientHello contents escaped")
	}
	s.Client.Records[0].Length = 1
	if o.Snapshot().Client.Records[0].Length != 2048 {
		t.Fatal("snapshot aliases live metadata")
	}
}
func TestTLSWireMasksPayloadAndBoundsRecords(t *testing.T) {
	for _, data := range [][]byte{[]byte("Authorization: secret"), append([]byte{22, 3, 3, 0, 32}, bytes.Repeat([]byte{0x41}, 32)...), append([]byte{23, 3, 3, 0, 32}, bytes.Repeat([]byte{0x42}, 32)...)} {
		var o TLSWireObserver
		o.ObserveOrigin(data)
		raw, _ := json.Marshal(o.Snapshot())
		if bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte("414141")) || bytes.Contains(raw, []byte("424242")) {
			t.Fatal(string(raw))
		}
	}
	var o TLSWireObserver
	for i := 0; i < 1000; i++ {
		o.ObserveClient([]byte{22, 3, 3, 0, 1, 0})
	}
	s := o.Snapshot()
	if len(s.Client.Records) != 8 || !s.Client.Bounded || s.Client.Bytes != 6000 {
		t.Fatal(s)
	}
}

type tlsPartialWriter struct{}

func (tlsPartialWriter) Write([]byte) (int, error) { return 5, io.ErrShortWrite }
func TestTLSWireCountsOnlySuccessfulWritesIncludingPartialError(t *testing.T) {
	o := &TLSWireObserver{}
	e := &tunnelCloseEvidence{tlsWire: o}
	n, err := (closeWriter{Writer: tlsPartialWriter{}, evidence: e}).Write([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	if n != 5 || !errors.Is(err, io.ErrShortWrite) || o.Snapshot().Client.Bytes != 5 || o.Snapshot().Client.State != "TLS_HEADER_ONLY" {
		t.Fatal(n, err, o.Snapshot())
	}
}

func TestTLSWireServerHelloHeaderSplitAcrossRecordsIsNotPrematureProgress(t *testing.T) {
	var wire TLSWireObserver
	first := []byte{22, 3, 3, 0, 2, 2, 0}
	second := append([]byte{22, 3, 3, 0, 40, 0, 38}, make([]byte, 38)...)
	wire.ObserveOrigin(first)
	if wire.Snapshot().Origin.ServerHelloComplete {
		t.Fatal("record completion confused with ServerHello completion")
	}
	for i, b := range second {
		wire.ObserveOrigin([]byte{b})
		if i < len(second)-1 && wire.Snapshot().Origin.ServerHelloComplete {
			t.Fatal("truncated ServerHello confirmed")
		}
	}
	if !wire.Snapshot().Origin.ServerHelloComplete {
		t.Fatal("complete fragmented ServerHello not detected")
	}
}

func TestTLSWireTinyServerHelloCannotConfirmHealth(t *testing.T) {
	for _, n := range []byte{0, 4, 37} {
		var wire TLSWireObserver
		wire.ObserveOrigin(append([]byte{22, 3, 3, 0, n + 4, 2, 0, 0, n}, make([]byte, n)...))
		if wire.Snapshot().Origin.ServerHelloComplete {
			t.Fatal("undersized ServerHello confirmed", n)
		}
	}
}

func TestServerHelloEndOffsetAcrossReadsAndRecords(t *testing.T) {
	hello := append([]byte{2, 0, 0, 38}, make([]byte, 38)...)
	first := append([]byte{22, 3, 3, 0, 10}, hello[:10]...)
	second := append([]byte{22, 3, 3, 0, 32}, hello[10:]...)
	wire := append(first, second...)
	wire = append(wire, 23, 3, 3, 0, 1, 0)
	for split := 1; split < len(wire); split++ {
		var o TLSWireObserver
		o.ObserveOrigin(wire[:split])
		o.ObserveOrigin(wire[split:])
		s := o.Snapshot().Origin
		if !s.ServerHelloComplete || s.ServerHelloEndBytes != 52 || s.Bytes != 58 {
			t.Fatal(split, s)
		}
	}
}

func TestWireCountsCompletedApplicationRecordsPastRetainedHistory(t *testing.T) {
	var o TLSWireObserver
	for i := 0; i < 100; i++ {
		o.ObserveOrigin([]byte{23, 3, 3, 0, 2, 1})
		o.ObserveOrigin([]byte{2})
	}
	s := o.Snapshot().Origin
	if len(s.Records) != 8 || !s.Bounded || s.ApplicationRecords != 100 || s.ApplicationBytes != 200 || s.TotalRecords != 100 {
		t.Fatal(s)
	}
	o.ObserveOrigin([]byte{23, 3, 3, 0, 10, 0})
	if o.Snapshot().Origin.ApplicationRecords != 100 {
		t.Fatal("partial record counted as completed")
	}
}
