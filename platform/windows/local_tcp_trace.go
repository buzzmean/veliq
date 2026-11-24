package windowsplatform

import (
	"encoding/binary"
	"github.com/buzzmean/veliq/core/localstrategy"
	"time"
)

// Observed network direction, not authenticated attribution: a remote RST can
// be forged by a middlebox. TTL is evidence, never sufficient to label DPI.
func (l *EvidenceLedger) RecordLocalTCPPacket(id ProcessIdentity, t Tuple, p []byte, remote bool) {
	if len(p) < 40 || p[0] != 0x45 || p[9] != 6 {
		return
	}
	h := 20 + int(p[32]>>4)*4
	if h < 40 || h > len(p) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	v, ok := l.lookupLocked(k)
	if !ok {
		return
	}
	trace := localstrategy.TCPTrace{}
	if v.LocalTCP != nil {
		trace = *v.LocalTCP
	}
	trace.Observed++
	flags := p[33]
	seq := binary.BigEndian.Uint32(p[24:])
	// SYN establishes relative sequence origin. Hot-attached flows without SYN
	// remain UNKNOWN; never call an absolute/wrapped RST sequence "small".
	if flags&2 != 0 {
		timestamp := false
		for i := 40; i < h; {
			if p[i] == 0 {
				break
			}
			if p[i] == 1 {
				i++
				continue
			}
			if i+1 >= h || p[i+1] < 2 || i+int(p[i+1]) > h {
				break
			}
			if p[i] == 8 && p[i+1] == 10 {
				timestamp = true
			}
			i += int(p[i+1])
		}
		if remote {
			trace.RemoteSYNSeen = true
			trace.RemoteSYNTimestamp = timestamp
			trace.RemoteBase = seq + 1
			trace.RemoteBaseKnown = true
		} else {
			trace.ClientSYNSeen = true
			trace.ClientSYNTimestamp = timestamp
			trace.ClientBase = seq + 1
			trace.ClientBaseKnown = true
		}
	}
	if remote && flags&4 != 0 && trace.RemoteBaseKnown {
		delta := int32(seq - trace.RemoteBase)
		if delta >= 0 {
			trace.RemoteRSTRelative = uint32(delta)
			trace.RemoteRSTRelativeKnown = true
		}
	}
	if remote {
		trace.LastRemoteTTL = p[8]
		if flags&0x12 == 0x12 {
			trace.SYNACKTTL = p[8]
		}
		if len(p) > h {
			trace.LastRemotePayloadAt = time.Now()
			trace.RemotePayloadPackets++
			trace.RemotePayloadBytes += uint64(len(p) - h)
		}
		if flags&4 != 0 {
			trace.RemoteRST++
			trace.RemoteTerminalTTL = p[8]
		}
		if flags&1 != 0 {
			trace.RemoteFIN++
			trace.RemoteTerminalTTL = p[8]
		}
	} else {
		if len(p) > h {
			trace.ClientPayloadPackets++
			trace.ClientPayloadBytes += uint64(len(p) - h)
		}
		if flags&4 != 0 {
			trace.ClientRST++
			trace.ClientTerminalTTL = p[8]
		}
		if flags&1 != 0 {
			trace.ClientFIN++
			trace.ClientTerminalTTL = p[8]
		}
	}
	if trace.FirstClose == "" && flags&5 != 0 {
		trace.FirstClose = "CLIENT_PACKET"
		if remote {
			trace.FirstClose = "REMOTE_PACKET"
		}
		trace.FirstCloseFlags = flags
		trace.FirstCloseTTL = p[8]
		trace.FirstCloseAt = time.Now()
		trace.LastRemoteBeforeCloseAt = trace.LastRemotePayloadAt
	}
	// Relative TCP serial arithmetic stays private; never export absolute seq/ack.
	end := seq + uint32(len(p)-h)
	if remote {
		if len(p) > h && trace.RemoteSequenceSeen && int32(seq-trace.RemoteNext) < 0 {
			trace.RemoteRetransmits++
		}
		trace.RemoteSequenceSeen = trace.RemoteSequenceSeen || len(p) > h
		if int32(end-trace.RemoteNext) > 0 || trace.RemoteNext == 0 {
			trace.RemoteNext = end
		}
	} else {
		if len(p) > h && trace.ClientSequenceSeen && int32(seq-trace.ClientNext) < 0 {
			trace.ClientRetransmits++
			if trace.ClientBaseKnown && int32(seq-trace.ClientBase) >= 0 && seq-trace.ClientBase < 32768 {
				trace.ClientEarlyRetransmits++
			}
		}
		trace.ClientSequenceSeen = trace.ClientSequenceSeen || len(p) > h
		if int32(end-trace.ClientNext) > 0 || trace.ClientNext == 0 {
			trace.ClientNext = end
		}
	}
	v.LocalTCP = &trace
	l.storeLocked(k, v)
}
