package localstrategy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestPassiveHelloInspection(t *testing.T) {
	hello := fakeHello()
	noSNI := append([]byte(nil), hello...)
	// The independently generated hello has one extension; use an unknown type
	// without changing any lengths to verify a complete, absent server_name.
	noSNI[52] = 0xfe
	noSNI[53] = 0xfe
	malformed := append([]byte(nil), hello...)
	malformed[43] = 255
	spanning := append([]byte(nil), hello...)
	spanning[8]++
	for _, tc := range []struct {
		name string
		p    []byte
		want string
	}{
		{"short record", hello[:3], "CLIENTHELLO_INCOMPLETE"},
		{"fragmented hello", hello[:len(hello)-4], "CLIENTHELLO_INCOMPLETE"},
		{"multiple records", spanning, "CLIENTHELLO_INCOMPLETE"},
		{"no SNI", noSNI, "SNI_NOT_FOUND"},
		{"malformed", malformed, "NO_TRANSFORM"},
		{"not TLS", []byte("opaque"), "NO_TRANSFORM"},
		{"complete", hello, "NO_TRANSFORM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := append([]byte(nil), tc.p...)
			d := inspectHello(raw)
			if d.Reason != tc.want || !bytes.Equal(raw, tc.p) {
				t.Fatalf("%+v", d)
			}
			if tc.name == "complete" && d.Domain != "www.example.org" {
				t.Fatal(d)
			}
		})
	}
}
func TestInspectionDoesNotChangeFlowDecisions(t *testing.T) {
	p := chainProfile(Action{Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1}})
	p.IPs = nil
	p.Domains = []string{"another.example"}
	e := engine(t, p)
	st := &State{}
	raw := tlsInput(100)
	r := e.Process(raw, st, metadata())
	if r.Modified || r.Active || r.Inspection == nil || r.Inspection.Reason != "DOMAIN_NOT_MATCHED" || r.Inspection.Domain != "www.example.org" {
		t.Fatalf("%+v", r)
	}
	p.Domains = []string{"www.example.org"}
	e = engine(t, p)
	st = &State{}
	raw = packet(6, fakeHello()[:30])
	r = e.Process(raw, st, metadata())
	if r.Modified || r.Inspection == nil || r.Inspection.Reason != "CLIENTHELLO_INCOMPLETE" {
		t.Fatal(r)
	}
	// ACK/pass-through cannot replace the first-payload diagnosis.
	ack := packet(6, nil)
	ack[33] = 16
	if e.Process(ack, st, metadata()).Inspection != nil {
		t.Fatal("ACK produced payload diagnosis")
	}
}
func FuzzPassiveInspection(f *testing.F) {
	f.Add(fakeHello())
	f.Add([]byte{22, 3, 1, 0, 1, 1})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 65535 {
			return
		}
		before := append([]byte(nil), p...)
		d := inspectHello(p)
		if d == nil || !bytes.Equal(before, p) || len(d.Domain) > 253 {
			t.Fatal("unbounded/mutating diagnostic")
		}
		if d.RecordBytes < 0 || d.HandshakeBytes < 0 {
			t.Fatal("invalid lengths")
		}
	})
}

// Ensure malformed advertised lengths cannot become SNI_NOT_FOUND.
func TestMalformedHelloLengthNotMissingSNI(t *testing.T) {
	p := fakeHello()
	binary.BigEndian.PutUint16(p[3:5], 1)
	if inspectHello(p).Reason == "SNI_NOT_FOUND" {
		t.Fatal("malformed TLS mislabeled")
	}
}

func TestEligibilityGuardKeepsPassiveInspection(t *testing.T) {
	e := engine(t, chainProfile(Action{Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1}}))
	e.Guard = func(Metadata) bool { return false }
	r := e.Process(tlsInput(100), &State{}, metadata())
	if r.Modified || r.Inspection == nil || r.Inspection.Domain != "www.example.org" || r.Inspection.Reason != "NO_TRANSFORM" {
		t.Fatal(r)
	}
}

func TestZeroReassemblyElapsedIsNotOmitted(t *testing.T) {
	b, err := json.Marshal(Inspection{Reason: "REASSEMBLY_COMPLETE", ReassemblyMS: 0})
	if err != nil || !bytes.Contains(b, []byte(`"reassembly_ms":0`)) {
		t.Fatal(string(b), err)
	}
}
