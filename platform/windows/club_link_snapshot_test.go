package windowsplatform

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func clubTCPFixture(ipv6 bool, peers []string, states []uint32, pids []uint32) []byte {
	width := 24
	if ipv6 {
		width = 56
	}
	b := make([]byte, 4+width*len(peers))
	binary.LittleEndian.PutUint32(b, uint32(len(peers)))
	for i, peer := range peers {
		p := netip.MustParseAddrPort(peer)
		r := b[4+i*width : 4+(i+1)*width]
		if ipv6 {
			addr := p.Addr().As16()
			copy(r[24:40], addr[:])
			binary.BigEndian.PutUint16(r[44:46], p.Port())
			binary.LittleEndian.PutUint32(r[48:52], states[i])
			binary.LittleEndian.PutUint32(r[52:56], pids[i])
		} else {
			addr := p.Addr().As4()
			copy(r[12:16], addr[:])
			binary.BigEndian.PutUint16(r[16:18], p.Port())
			binary.LittleEndian.PutUint32(r[:4], states[i])
			binary.LittleEndian.PutUint32(r[20:24], pids[i])
		}
	}
	return b
}

func TestClubLinkNativeTablesRequireCompletePrivateEstablishedRows(t *testing.T) {
	for _, fixture := range []struct {
		v6    bool
		peers []string
	}{
		{false, []string{"10.2.3.4:9917", "203.0.113.1:9917", "127.0.0.1:9917", "10.2.3.5:9917"}},
		{true, []string{"[fd01::2]:9917", "[2001:db8::1]:9917", "[fe80::1]:9917", "[fd01::3]:9917"}},
	} {
		raw := clubTCPFixture(fixture.v6, fixture.peers, []uint32{5, 5, 5, 8}, []uint32{24, 24, 24, 24})
		rows, err := decodeClubLinkTCPTable(raw, fixture.v6)
		if err != nil || len(rows) != 1 || rows[0].Peer != netip.MustParseAddrPort(fixture.peers[0]) || rows[0].PID != 24 {
			t.Fatalf("v6=%v rows=%+v err=%v", fixture.v6, rows, err)
		}
		if _, err = decodeClubLinkTCPTable(raw[:len(raw)-1], fixture.v6); err == nil {
			t.Fatal("partial table was accepted as absence proof")
		}
		binary.LittleEndian.PutUint32(raw, clubLinkTCPRowLimit+1)
		if _, err = decodeClubLinkTCPTable(raw, fixture.v6); err == nil {
			t.Fatal("excessive native row count accepted")
		}
	}
	if rows, err := decodeClubLinkTCPTable([]byte{0, 0, 0, 0}, false); err != nil || len(rows) != 0 {
		t.Fatal("successful empty table conflated with failure")
	}
	raw := clubTCPFixture(false, []string{"10.2.3.4:9917"}, []uint32{99}, []uint32{24})
	if _, err := decodeClubLinkTCPTable(raw, false); err == nil {
		t.Fatal("invalid native state accepted")
	}
}

func TestClubLinkNativeOwnerRequiresSCMGenerationAndDirectWorker(t *testing.T) {
	root := ProcessIdentity{PID: 24, CreationTime: 10, Path: `C:\LanGame\LanGameService.exe`}
	worker := ProcessIdentity{PID: 28, CreationTime: 11, Path: root.Path, ParentPID: root.PID, ParentCreationTime: root.CreationTime}
	peer := netip.MustParseAddrPort("10.2.3.4:9917")
	row := clubLinkTCPRow{Peer: peer, PID: worker.PID, State: 5, Protocol: "TCP4"}
	check := func(id ProcessIdentity, lookupErr error) ClubLinkSnapshot {
		t.Helper()
		snapshot, err := filterClubLinkTCPRows(root, []clubLinkTCPRow{row}, func(uint32) (ProcessIdentity, error) { return id, lookupErr }, 100)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	if s := check(worker, nil); len(s.Sockets) != 1 || s.Sockets[0].Identity != worker {
		t.Fatal("SCM worker not recognized")
	}
	worker.ParentCreationTime++
	if s := check(worker, nil); len(s.Sockets) != 0 {
		t.Fatal("reused parent PID trusted")
	}
	worker.ParentCreationTime--
	worker.Path = `C:\Other\LanGameService.exe`
	if s := check(worker, nil); len(s.Sockets) != 0 {
		t.Fatal("lookalike executable trusted")
	}
	if s := check(ProcessIdentity{}, errors.New("unavailable")); len(s.Sockets) != 0 || len(s.UnknownPeers) != 1 || s.UnknownPeers[0] != peer {
		t.Fatal("unreadable owner became absent")
	}
	rootAgain := root
	rootAgain.CreationTime++
	row.PID = root.PID
	if s := check(rootAgain, nil); len(s.Sockets) != 0 {
		t.Fatal("new process generation inherited old root identity")
	}
	rootAgain = root
	rootAgain.CreationTime = 101
	if s := check(rootAgain, nil); len(s.UnknownPeers) != 1 {
		t.Fatal("process born after table snapshot was trusted")
	}
}

func TestClubLinkSCMStopOrRestartDoesNotHideEstablishedOrphanWorker(t *testing.T) {
	oldRoot := ProcessIdentity{PID: 24, CreationTime: 10, Path: `C:\LanGame\LanGameService.exe`}
	worker := ProcessIdentity{PID: 28, CreationTime: 11, Path: oldRoot.Path, ParentPID: oldRoot.PID, ParentCreationTime: oldRoot.CreationTime}
	peer := netip.MustParseAddrPort("10.2.3.4:9917")
	rows := []clubLinkTCPRow{{Peer: peer, PID: worker.PID, State: 5, Protocol: "TCP4"}}
	lookup := func(uint32) (ProcessIdentity, error) { return worker, nil }
	baseline, err := filterClubLinkTCPRows(oldRoot, rows, lookup, 100)
	if err != nil || len(baseline.Sockets) != 1 {
		t.Fatal("verified direct worker baseline missing", err)
	}
	for name, root := range map[string]ProcessIdentity{
		"SCM stopped":    {},
		"SCM restarted":  {PID: 32, CreationTime: 20, Path: oldRoot.Path},
		"SCM PID reused": {PID: oldRoot.PID, CreationTime: 20, Path: oldRoot.Path},
	} {
		t.Run(name, func(t *testing.T) {
			for range 2 {
				snapshot, err := filterClubLinkTCPRows(root, rows, lookup, 100)
				if err != nil || len(snapshot.Sockets) != 0 || len(snapshot.UnknownPeers) != 1 || snapshot.UnknownPeers[0] != peer {
					t.Fatal("established orphan socket became absence proof or trusted owner", snapshot, err)
				}
			}
			empty, err := filterClubLinkTCPRows(root, nil, lookup, 100)
			if err != nil || len(empty.Sockets) != 0 || len(empty.UnknownPeers) != 0 {
				t.Fatal("actual empty full TCP table was not preserved", empty, err)
			}
		})
	}
	// A same-name executable gains no SCM trust. A positively identified foreign
	// application can be skipped; neither is promoted to a verified LanGame socket.
	worker.Path = `C:\Other\LanGameService.exe`
	lookalike, err := filterClubLinkTCPRows(oldRoot, rows, lookup, 100)
	if err != nil || len(lookalike.Sockets) != 0 || len(lookalike.UnknownPeers) != 1 {
		t.Fatal("lookalike granted trust or its ambiguity hidden", lookalike, err)
	}
	worker.Path = `C:\Other\chrome.exe`
	foreign, err := filterClubLinkTCPRows(oldRoot, rows, lookup, 100)
	if err != nil || len(foreign.Sockets) != 0 || len(foreign.UnknownPeers) != 0 {
		t.Fatal("positively identified foreign application was trusted", foreign, err)
	}
}
