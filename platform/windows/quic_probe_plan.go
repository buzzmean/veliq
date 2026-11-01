package windowsplatform

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
)

// QUICProbeScope is an explicit service-probe identity, not DNS inference for an
// opaque browser packet. No capture or Classify path constructs this writer.
type QUICProbeScope struct {
	Owner                      ProcessIdentity
	Source, Destination        netip.AddrPort
	Network, Profile, Revision string
}
type QUICProbeSendEvidence struct {
	FakePackets, OriginalPackets uint64
	Committed, Failed            bool
}

// QUICProbeWriter sends at most one decoy flight, on one immutable tuple. It has
// no dial, relay, packet queue or replay function. Its caller supplies a live
// process AND network/profile/revision check, evaluated before every send.
type QUICProbeWriter struct {
	mu       sync.Mutex
	scope    QUICProbeScope
	repeats  uint8
	current  func(QUICProbeScope) bool
	started  bool
	evidence QUICProbeSendEvidence
}

func NewQUICProbeWriter(scope QUICProbeScope, repeats uint8, current func(QUICProbeScope) bool) (*QUICProbeWriter, error) {
	app := strings.ToLower(filepath.Base(strings.ReplaceAll(scope.Owner.Path, `\`, "/")))
	browser := app == "chrome.exe" || app == "msedge.exe" || app == "brave.exe" || app == "browser.exe" || app == "opera.exe" || app == "firefox.exe"
	ownerValid := browser && scope.Owner.PID != 0 && scope.Owner.CreationTime != 0 && len(scope.Owner.Path) <= 2048
	sourceValid := scope.Source.IsValid() && scope.Source.Addr().Is4() && !scope.Source.Addr().IsUnspecified() && !scope.Source.Addr().IsMulticast() && scope.Source.Port() != 0
	destinationValid := scope.Destination.Addr().Is4() && browserproxy.PublicDNSAddress(scope.Destination.Addr()) && scope.Destination.Port() == 443
	policyValid := scope.Network != "" && scope.Profile != "" && scope.Revision != "" && len(scope.Network) <= 256 && len(scope.Profile) <= 128 && len(scope.Revision) <= 128
	if !ownerValid || !sourceValid || !destinationValid || !policyValid || repeats < 1 || repeats > localstrategy.QUICProbeMaxRepeats || current == nil {
		return nil, errors.New("QUIC_PROBE_SCOPE_INVALID")
	}
	return &QUICProbeWriter{scope: scope, repeats: repeats, current: current}, nil
}

func (w *QUICProbeWriter) Evidence() QUICProbeSendEvidence {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.evidence.Failed && !w.current(w.scope) {
		w.evidence.Failed, w.evidence.Committed = true, false
	}
	return w.evidence
}

// Every send error is terminal, including an uncertain original send. No second
// callback invocation can resubmit that packet or inherit a committed witness.
func (w *QUICProbeWriter) Send(packet []byte, send func([]byte) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	fail := func(err error) error { w.evidence.Failed = true; w.evidence.Committed = false; return err }
	if w.evidence.Failed {
		return errors.New("QUIC_PROBE_WRITER_FAILED")
	}
	tuple, _, err := ParseUDP(packet)
	if err != nil || len(packet) > 1500 || tuple.Source != w.scope.Source || tuple.Destination != w.scope.Destination || send == nil || !w.current(w.scope) {
		return fail(errors.New("QUIC_PROBE_SCOPE_CHANGED"))
	}
	first := !w.started
	w.started = true
	packets := [][]byte{packet}
	if first {
		packets, err = localstrategy.QUICInitialPlan(packet, w.repeats)
		if err != nil {
			return fail(err)
		}
	}
	for i, p := range packets {
		if !w.current(w.scope) {
			return fail(errors.New("QUIC_PROBE_SCOPE_CHANGED"))
		}
		if err = send(p); err != nil {
			return fail(err)
		}
		if first && i < len(packets)-1 {
			w.evidence.FakePackets++
		} else {
			w.evidence.OriginalPackets++
		}
	}
	if !w.current(w.scope) {
		return fail(errors.New("QUIC_PROBE_SCOPE_CHANGED"))
	}
	if first {
		w.evidence.Committed = true
	}
	return nil
}
