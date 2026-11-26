package windowsplatform

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const clubLinkTCPRowLimit = 32768

// ClubLinkSocket contains only a positively verified SCM-owned LanGame socket.
// Addresses are local-only input to the diagnostic producer, never its DTO.
type ClubLinkSocket struct {
	Identity ProcessIdentity
	Peer     netip.AddrPort
	Protocol string
}

// ClubLinkSnapshot is complete only when both native address families and SCM
// ownership were read successfully. An unreadable owner makes that peer unknown
// rather than absent. A successful empty snapshot is distinct from an error.
type ClubLinkSnapshot struct {
	Sockets      []ClubLinkSocket
	UnknownPeers []netip.AddrPort
}

type clubLinkTCPRow struct {
	Peer     netip.AddrPort
	PID      uint32
	State    uint32
	Protocol string
}

func decodeClubLinkTCPTable(raw []byte, ipv6 bool) ([]clubLinkTCPRow, error) {
	width := 24
	if ipv6 {
		width = 56
	}
	if len(raw) < 4 {
		return nil, errors.New("CLUB_LINK_TCP_TABLE_TRUNCATED")
	}
	n := uint64(binary.LittleEndian.Uint32(raw))
	if n > clubLinkTCPRowLimit || n*uint64(width) > uint64(len(raw)-4) {
		return nil, errors.New("CLUB_LINK_TCP_TABLE_BOUND")
	}
	rows := make([]clubLinkTCPRow, 0, n)
	for i := 0; i < int(n); i++ {
		r := raw[4+i*width : 4+(i+1)*width]
		var row clubLinkTCPRow
		if ipv6 {
			var address [16]byte
			copy(address[:], r[24:40])
			// Scoped/link-local peers cannot identify a private club service here.
			if binary.LittleEndian.Uint32(r[40:44]) != 0 {
				continue
			}
			row.Peer = netip.AddrPortFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(r[44:46]))
			row.State, row.PID = binary.LittleEndian.Uint32(r[48:52]), binary.LittleEndian.Uint32(r[52:56])
			row.Protocol = "TCP6"
		} else {
			var address [4]byte
			copy(address[:], r[12:16])
			row.Peer = netip.AddrPortFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(r[16:18]))
			row.State, row.PID = binary.LittleEndian.Uint32(r[:4]), binary.LittleEndian.Uint32(r[20:24])
			row.Protocol = "TCP4"
		}
		if row.State < 1 || row.State > 12 {
			return nil, errors.New("CLUB_LINK_TCP_STATE_INVALID")
		}
		if row.State == 5 && row.PID != 0 && row.Peer.Port() != 0 &&
			row.Peer.Addr().IsPrivate() && !row.Peer.Addr().Is4In6() {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func filterClubLinkTCPRows(root ProcessIdentity, rows []clubLinkTCPRow, lookup func(uint32) (ProcessIdentity, error), started uint64) (ClubLinkSnapshot, error) {
	out := ClubLinkSnapshot{}
	if root.PID == 0 {
		return out, nil // The service was positively observed stopped.
	}
	ids := map[uint32]ProcessIdentity{}
	for _, row := range rows {
		id, read := ids[row.PID]
		if !read {
			if len(ids) >= 128 {
				return ClubLinkSnapshot{}, errors.New("CLUB_LINK_OWNER_BOUND")
			}
			id, _ = lookup(row.PID)
			ids[row.PID] = id
		}
		if id.PID == 0 || id.PID != row.PID || id.CreationTime == 0 || id.CreationTime > started {
			out.UnknownPeers = append(out.UnknownPeers, row.Peer)
			continue
		}
		if !lanGameOwnershipMatches(id, id, root) {
			continue
		}
		out.Sockets = append(out.Sockets, ClubLinkSocket{Identity: id, Peer: row.Peer, Protocol: row.Protocol})
	}
	return out, nil
}
