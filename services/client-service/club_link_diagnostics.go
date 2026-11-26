package clientservice

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/security"
	wp "github.com/buzzmean/veliq/platform/windows"
)

const clubLinkInterval = 2 * time.Second
const clubLinkPeers = 64

type clubPeerKey struct {
	peer     netip.AddrPort
	protocol string
}

type clubPeerState struct {
	peerID, linkID  string
	owner           wp.ProcessIdentity
	lastEstablished time.Time
	missing         int
	lost            bool
}

type clubLinkFact struct {
	link  clubhealth.ClubLink
	owner wp.ProcessIdentity
}

type clubLinkTracker struct {
	peers      map[clubPeerKey]*clubPeerState
	lastSample time.Time
}

func (t *clubLinkTracker) resetConfirmation() {
	for _, peer := range t.peers {
		peer.missing = 0
	}
	t.lastSample = time.Time{}
}

// observe groups all established sockets by the real peer, not the ephemeral
// local socket. A replacement connection to that peer is not a loss. Two full
// successful snapshots must agree; errors and gaps never supply absence proof.
func (t *clubLinkTracker) observe(snapshot wp.ClubLinkSnapshot, sampleErr error, at time.Time) []clubLinkFact {
	if sampleErr != nil || len(snapshot.Sockets) > clubLinkPeers*16 || len(snapshot.UnknownPeers) > clubLinkPeers*16 {
		t.resetConfirmation()
		return nil
	}
	if t.peers == nil {
		t.peers = map[clubPeerKey]*clubPeerState{}
	}
	current := map[clubPeerKey]wp.ProcessIdentity{}
	for _, socket := range snapshot.Sockets {
		name := socket.Identity.Path[strings.LastIndexAny(socket.Identity.Path, `/\`)+1:]
		if socket.Identity.PID == 0 || socket.Identity.CreationTime == 0 || !strings.EqualFold(name, "LanGameService.exe") ||
			!socket.Peer.IsValid() || socket.Peer.Port() == 0 || !socket.Peer.Addr().IsPrivate() || socket.Peer.Addr().Is4In6() ||
			(socket.Protocol != "TCP4" && socket.Protocol != "TCP6") || (socket.Protocol == "TCP4") != socket.Peer.Addr().Is4() {
			t.resetConfirmation()
			return nil
		}
		current[clubPeerKey{socket.Peer, socket.Protocol}] = socket.Identity
	}
	for key, peer := range t.peers {
		if at.Sub(peer.lastEstablished) > clubhealth.Retention {
			delete(t.peers, key)
		}
	}
	newPeers := 0
	for key := range current {
		if t.peers[key] == nil {
			newPeers++
		}
	}
	if len(t.peers)+newPeers > clubLinkPeers {
		t.resetConfirmation()
		return nil
	}
	if gap := at.Sub(t.lastSample); t.lastSample.IsZero() || gap <= 0 || gap > 2*clubLinkInterval {
		t.resetConfirmation()
	}
	t.lastSample = at
	unknown := map[netip.AddrPort]bool{}
	for _, peer := range snapshot.UnknownPeers {
		unknown[peer] = true
	}
	var facts []clubLinkFact
	for key, owner := range current {
		peer := t.peers[key]
		if peer == nil {
			id, err := security.NewID()
			if err != nil {
				continue
			}
			peer = &clubPeerState{peerID: id}
			t.peers[key] = peer
		}
		peer.owner, peer.lastEstablished, peer.missing = owner, at, 0
		if peer.lost {
			facts = append(facts, clubLinkFact{clubhealth.ClubLink{Kind: "LANGAME", LinkID: peer.linkID, PeerID: peer.peerID,
				Protocol: key.protocol, Event: "CONNECTION_RESTORED", Previous: "ABSENT", Current: "ESTABLISHED", LastEstablishedAt: at}, owner})
			peer.lost = false
		}
	}
	for key, peer := range t.peers {
		if _, exists := current[key]; exists || peer.lost {
			continue
		}
		if unknown[key.peer] || at.Before(peer.lastEstablished) {
			peer.missing = 0
			continue
		}
		peer.missing++
		if peer.missing < 2 {
			continue
		}
		id, err := security.NewID()
		if err != nil {
			continue
		}
		peer.linkID, peer.lost = id, true
		facts = append(facts, clubLinkFact{clubhealth.ClubLink{Kind: "LANGAME", LinkID: id, PeerID: peer.peerID,
			Protocol: key.protocol, Event: "CONNECTION_LOST", Previous: "ESTABLISHED", Current: "ABSENT", LastEstablishedAt: peer.lastEstablished}, peer.owner})
	}
	return facts
}

func (d *persistentDiagnostics) observeClubLinks(ctx context.Context) {
	ticker := time.NewTicker(clubLinkInterval)
	defer ticker.Stop()
	var tracker clubLinkTracker
	for {
		snapshot, err := wp.PassiveClubLinks()
		at := time.Now().UTC()
		if err != nil {
			d.note("CLUB_LINK_OBSERVER", "PASSIVE_TCP_TABLE", "unknown", "SNAPSHOT_UNAVAILABLE", 0, "club-link-observer")
		} else {
			d.note("CLUB_LINK_OBSERVER", "PASSIVE_TCP_TABLE", "ready", "SNAPSHOT_COMPLETE", 0, "club-link-observer")
		}
		for _, fact := range tracker.observe(snapshot, err, at) {
			e := d.event("CLUB_LINK", "PASSIVE_TCP_TABLE", "failed", fact.link.Event)
			e.At, e.ClubLink, e.Incident = at, fact.link, fact.link.LinkID
			e.PID, e.Birth, e.App, e.ProcessVerified = fact.owner.PID, fact.owner.CreationTime, "langameservice.exe", true
			if fact.link.Event == "CONNECTION_RESTORED" {
				e.State = "recovered" // TCP was observed again; no application recovery is attempted.
			}
			select {
			case d.clubInputs <- diagnosticInput{event: e}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *persistentDiagnostics) wakeDiagnosticUpload() {
	select {
	case d.uploadWake <- struct{}{}:
	default:
	}
}

// Give new connection facts room ahead of a large old journal while retaining
// half of each batch for existing lifecycle/backlog diagnostics.
func clubLinkDiagnosticBatch(j clubhealth.Journal) clubhealth.Batch {
	var urgent []clubhealth.Diagnostic
	for _, rows := range [][]clubhealth.JournalRow{j.Rows, j.History} {
		for _, row := range rows {
			if !row.Acked && !row.Event.ClubLink.IsZero() && len(urgent) < clubhealth.MaxEvents {
				urgent = append(urgent, row.Event)
			}
		}
	}
	if len(urgent) == 0 {
		return j.Batch()
	}
	ordinary := clubhealth.Journal{}
	for _, queues := range []struct {
		from []clubhealth.JournalRow
		to   *[]clubhealth.JournalRow
	}{{j.Rows, &ordinary.Rows}, {j.History, &ordinary.History}} {
		for _, row := range queues.from {
			if !row.Acked && row.Event.ClubLink.IsZero() {
				*queues.to = append(*queues.to, row)
			}
		}
	}
	first := min(len(urgent), clubhealth.MaxEvents/2)
	b := clubhealth.Batch{Protocol: 1, Events: append([]clubhealth.Diagnostic(nil), urgent[:first]...)}
	for _, e := range ordinary.Batch().Events {
		if len(b.Events) < clubhealth.MaxEvents {
			b.Events = append(b.Events, e)
		}
	}
	for _, e := range urgent[first:] {
		if len(b.Events) < clubhealth.MaxEvents {
			b.Events = append(b.Events, e)
		}
	}
	return b
}

func waitDiagnosticUpload(ctx context.Context, delay time.Duration, wake <-chan struct{}, retryNotBefore time.Time) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-wake:
			if !time.Now().Before(retryNotBefore) {
				return true
			}
		}
	}
}
