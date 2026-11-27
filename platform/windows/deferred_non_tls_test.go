package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/routing"
)

type nonTLSReadFixture struct {
	deferredStreamFixture
	writes int
}

func (c *nonTLSReadFixture) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

func TestDeferredNonTLSBinaryPrefixBoundaryAndOriginalBytes(t *testing.T) {
	// Exercise every leading byte, including all TLS record types, SSLv2-like
	// prefixes, whitespace and unknown printable protocols. Only the deliberately
	// narrow control-byte contract can become NON_TLS_BINARY.
	for first := 0; first < 256; first++ {
		for _, chunk := range []int{1, 2, 7, 4096} {
			t.Run(fmt.Sprintf("%02x/chunk%d", first, chunk), func(t *testing.T) {
				wire := []byte{byte(first), 0xde, 0xad, 0xbe, 0xef, 0, 23, 3, 3}
				c := &nonTLSReadFixture{deferredStreamFixture: deferredStreamFixture{data: append([]byte(nil), wire...), chunk: chunk}}
				prefix, domain, reason := ReadDeferredHello(c)
				wantBinary := first < 20 && first != '\t' && first != '\r' && first != '\n'
				if (reason == "NON_TLS_BINARY") != wantBinary || domain != "" {
					t.Fatalf("domain=%q reason=%q, want binary=%v", domain, reason, wantBinary)
				}
				wantReads := (4 + chunk - 1) / chunk
				if wantBinary && c.reads != wantReads {
					t.Fatalf("four-byte framing used %d reads, want %d", c.reads, wantReads)
				}
				tail, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(append(prefix, tail...), wire) || c.writes != 0 {
					t.Fatalf("pre-read changed/replayed the stream: err=%v writes=%d", err, c.writes)
				}
			})
		}
	}
}

// A syntactically complete ClientHello with no SNI. The optional ECH extension
// is outer metadata only; this fixture never establishes a TLS connection.
func nonTLSGateHello(ech bool) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	var extensions []byte
	if ech {
		extensions = []byte{0xfe, 0x0d, 0, 0}
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	wire := binary.BigEndian.AppendUint16([]byte{22, 3, 3}, uint16(len(hello)))
	return append(wire, hello...)
}

func TestDeferredNonTLSDoesNotReclassifyHTTPOrTLS(t *testing.T) {
	// SSLv2 also permits a three-byte record header with its high bit clear.
	// This complete CLIENT-HELLO has one cipher and a 16-byte challenge.
	legacyThreeByteHello := append([]byte{0, 28, 0, 1, 0, 2, 0, 3, 0, 0, 0, 16, 1, 0, 128}, bytes.Repeat([]byte{0x11}, 16)...)
	for _, tc := range []struct {
		name, domain, reason string
		wire                 []byte
	}{
		{"http", "ordinary.example", "HTTP_HOST", []byte("GET / HTTP/1.1\r\nHost: ordinary.example\r\n\r\n")},
		{"tls", "web.telegram.org", "REASSEMBLY_COMPLETE", deferredMLKEMHello(t)},
		{"no-sni", "", "SNI_NOT_FOUND", nonTLSGateHello(false)},
		{"ech", "", "ECH_OUTER_SNI_ONLY", nonTLSGateHello(true)},
		{"tls-prefix", "", "CLIENTHELLO_INCOMPLETE", []byte{22, 3}},
		{"tls-body-incomplete", "", "CLIENTHELLO_INCOMPLETE", []byte{22, 3, 3, 0, 50, 1}},
		{"tls-malformed-length", "", "REASSEMBLY_LIMIT", []byte{22, 3, 3, 0, 0}},
		{"ssl2-like", "", "CLIENTHELLO_INCOMPLETE", []byte{0x80, 3, 1, 0, 2}},
		{"ssl2-three-byte-client-hello", "", "CLIENTHELLO_INCOMPLETE", legacyThreeByteHello},
		{"ssl2-three-byte-client-hello-prefix", "", "CLIENTHELLO_INCOMPLETE", legacyThreeByteHello[:4]},
		{"binary-short-one", "", "CLIENTHELLO_INCOMPLETE", []byte{1}},
		{"binary-short-two", "", "CLIENTHELLO_INCOMPLETE", []byte{1, 0}},
		{"binary-short-three", "", "CLIENTHELLO_INCOMPLETE", []byte{1, 0, 0}},
		{"ascii-unknown", "", "CLIENTHELLO_INCOMPLETE", []byte("GAME_HELLO")},
		{"empty", "", "CLIENT_CLOSED_BEFORE_DATA", nil},
	} {
		for _, chunk := range []int{1, 7, 4096} {
			t.Run(fmt.Sprintf("%s/chunk%d", tc.name, chunk), func(t *testing.T) {
				c := &nonTLSReadFixture{deferredStreamFixture: deferredStreamFixture{data: append([]byte(nil), tc.wire...), chunk: chunk}}
				prefix, domain, reason := ReadDeferredHello(c)
				tail, err := io.ReadAll(c)
				if domain != tc.domain || reason != tc.reason || !bytes.Equal(append(prefix, tail...), tc.wire) || err != nil || c.writes != 0 {
					t.Fatalf("domain=%q reason=%q err=%v writes=%d", domain, reason, err, c.writes)
				}
			})
		}
	}
}

func nonTLSGateDecision() Decision {
	return Decision{AllowNonTLSDirect: true, BlockOnFailure: true,
		Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: "auto_direct_default", Fallback: flowpolicy.FailOpen}}
}

func TestDeferredNonTLSDirectRequiresBothCapabilitiesAndUnchangedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		initial  bool
		reason   string
		mutate   func(*Decision)
		wantOpen bool
	}{
		{"ordinary-binary", true, "NON_TLS_BINARY", nil, true},
		{"initial-not-authorized", false, "NON_TLS_BINARY", nil, false},
		{"resolver-revoked", true, "NON_TLS_BINARY", func(d *Decision) { d.AllowNonTLSDirect = false }, false},
		{"explicit-block", true, "NON_TLS_BINARY", func(d *Decision) { d.Block = true; d.Policy.Action = flowpolicy.Block }, false},
		{"explicit-rule", true, "NON_TLS_BINARY", func(d *Decision) { d.Policy.Source = "rule" }, false},
		{"configured-baseline", true, "NON_TLS_BINARY", func(d *Decision) { d.Policy.Source = "configured_baseline" }, false},
		{"local-policy", true, "NON_TLS_BINARY", func(d *Decision) {
			d.Route = routing.Route{Kind: routing.DirectPlusRoute}
			d.Policy.Action = flowpolicy.DirectPlus
		}, false},
		{"relay-required-without-route", true, "NON_TLS_BINARY", func(d *Decision) { d.Policy.Action = flowpolicy.RelayRequired; d.Policy.Fallback = flowpolicy.Required }, false},
		{"relay-route-is-not-direct", true, "NON_TLS_BINARY", func(d *Decision) { d.Route = routing.Route{RelayID: "VPS-01"} }, false},
		{"incomplete", true, "CLIENTHELLO_INCOMPLETE", nil, false},
		{"malformed", true, "REASSEMBLY_LIMIT", nil, false},
		{"no-progress", true, "CLIENTHELLO_NO_PROGRESS", nil, false},
		{"no-sni", true, "SNI_NOT_FOUND", nil, false},
		{"ech", true, "ECH_OUTER_SNI_ONLY", nil, false},
		{"unobserved-domain", true, "DOMAIN_NOT_OBSERVED", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved := nonTLSGateDecision()
			if tc.mutate != nil {
				tc.mutate(&resolved)
			}
			calls := 0
			initial := Decision{AllowNonTLSDirect: tc.initial, BlockOnFailure: true, Deferred: true, ResolveDomain: func(domain string) Decision {
				calls++
				if domain != "" {
					t.Fatalf("unobserved origin was invented: %q", domain)
				}
				return resolved
			}}
			got := ResolveDeferredDecision(initial, "", tc.reason)
			if calls != 1 || got.Deferred || got.ResolveDomain != nil || !got.BlockOnFailure {
				t.Fatalf("resolver/state/failure floor changed: %+v calls=%d", got, calls)
			}
			if tc.wantOpen {
				if got.Block || !got.Route.Direct() || got.Route.Local() || got.Policy != resolved.Policy {
					t.Fatalf("ordinary non-TLS DIRECT was changed: %+v", got)
				}
			} else if !got.Block || got.Policy.Action != flowpolicy.Block {
				t.Fatalf("unapproved empty authority bypassed policy: %+v", got)
			}
		})
	}
}

func TestDeferredNonTLSDoesNotDowngradeAuthenticatedRelayOrMissingResolver(t *testing.T) {
	required := Decision{AllowNonTLSDirect: true, BlockOnFailure: true, Route: routing.Route{RelayID: "VPS-01"},
		Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Source: "rule", RelayID: "VPS-01", Fallback: flowpolicy.Required}}
	initial := Decision{AllowNonTLSDirect: true, Deferred: true, ResolveDomain: func(string) Decision { return required }}
	got := ResolveDeferredDecision(initial, "", "NON_TLS_BINARY")
	if got.Block || got.Route != required.Route || got.Policy != required.Policy || !got.BlockOnFailure {
		t.Fatalf("authenticated required route was downgraded: %+v", got)
	}
	got = ResolveDeferredDecision(Decision{AllowNonTLSDirect: true, BlockOnFailure: true, Deferred: true}, "", "NON_TLS_BINARY")
	if !got.Block || got.Policy.Action != flowpolicy.Block || got.Policy.Fallback != flowpolicy.FailBlock {
		t.Fatalf("capability replaced missing resolver: %+v", got)
	}
}
