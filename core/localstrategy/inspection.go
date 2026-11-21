package localstrategy

import (
	"encoding/binary"
	"strings"
	"time"
)

// Inspection is passive metadata from the first eligible payload, never retained
// packet bytes. A reason is not evidence that a packet was successfully sent.
type SentPacket struct {
	ACKOffset        int32 `json:"ack_offset"`
	TimestampPresent bool  `json:"timestamp_present"`
	TimestampDelta   int32 `json:"timestamp_delta"`
	MD5Present       bool  `json:"md5_present"`
	Fake             bool  `json:"fake"`
	SequenceOffset   int32 `json:"sequence_offset"`
	Flags            uint8 `json:"tcp_flags"`
	Length           int   `json:"length"`
	TTL              uint8 `json:"ttl"`
	Protocol         uint8 `json:"protocol"`
}

type TCPTrace struct {
	ClientSYNSeen, RemoteSYNSeen, ClientSYNTimestamp, RemoteSYNTimestamp               bool
	ClientEarlyRetransmits                                                             uint64 `json:"client_early_retransmits"`
	RemoteRSTRelative                                                                  uint32 `json:"remote_rst_relative"`
	RemoteRSTRelativeKnown                                                             bool   `json:"remote_rst_relative_known"`
	ClientBase, RemoteBase                                                             uint32 `json:"-"`
	ClientBaseKnown, RemoteBaseKnown                                                   bool   `json:"-"`
	Observed                                                                           uint64 `json:"observed"`
	ClientPayloadPackets, ClientPayloadBytes, RemotePayloadPackets, RemotePayloadBytes uint64
	ClientFIN, ClientRST, RemoteFIN, RemoteRST                                         uint64
	ClientRetransmits, RemoteRetransmits                                               uint64
	LastRemoteTTL, SYNACKTTL, ClientTerminalTTL, RemoteTerminalTTL                     uint8
	FirstClose                                                                         string    `json:"first_close,omitempty"`
	FirstCloseFlags                                                                    uint8     `json:"first_close_flags"`
	FirstCloseTTL                                                                      uint8     `json:"first_close_ttl"`
	FirstCloseAt                                                                       time.Time `json:"first_close_at"`
	LastRemotePayloadAt, LastRemoteBeforeCloseAt                                       time.Time
	ClientNext, RemoteNext                                                             uint32 `json:"-"`
	ClientSequenceSeen, RemoteSequenceSeen                                             bool   `json:"-"`
}

type Inspection struct {
	TransformSendMS          float64      `json:"transform_send_ms"`
	TCPPackets               TCPTrace     `json:"tcp_packets"`
	OriginalPacketBytes      int          `json:"original_packet_bytes"`
	TCPHeaderBytes           int          `json:"tcp_header_bytes"`
	TimestampOption          bool         `json:"timestamp_option"`
	SYNSeen                  bool         `json:"syn_seen"`
	HandshakeConfirmed       bool         `json:"handshake_confirmed"`
	ServerTTL                uint8        `json:"server_ttl"`
	SentPackets              []SentPacket `json:"sent_packets,omitempty"`
	ObservedSNI              string       `json:"observed_sni,omitempty"`
	SNIStatus                string       `json:"sni_status,omitempty"`
	SegmentsSeen             int          `json:"segments_seen,omitempty"`
	SegmentsBuffered         int          `json:"segments_buffered,omitempty"`
	BytesBuffered            int          `json:"bytes_buffered,omitempty"`
	ExpectedClientHelloBytes int          `json:"expected_clienthello_bytes,omitempty"`
	ReassemblyMS             int64        `json:"reassembly_ms"`
	OutOfOrder               bool         `json:"out_of_order,omitempty"`
	ReassembledSNI           bool         `json:"reassembled_sni,omitempty"`
	TransformApplied         bool         `json:"transform_applied"`

	OutputPacketsPlanned int  `json:"output_packets_planned,omitempty"`
	OutputPacketsSent    int  `json:"output_packets_sent,omitempty"`
	SendFailed           bool `json:"send_failed,omitempty"`

	Reason         string `json:"reason"`
	Detail         string `json:"detail,omitempty"`
	Domain         string `json:"domain,omitempty"`
	PayloadBytes   int    `json:"payload_bytes"`
	RecordBytes    int    `json:"record_bytes,omitempty"`
	HandshakeBytes int    `json:"handshake_bytes,omitempty"`
}

func inspectHello(p []byte) *Inspection {
	d := &Inspection{Reason: "NO_TRANSFORM", Detail: "not a recognized complete ClientHello", PayloadBytes: len(p)}
	if len(p) == 0 || len(p) > MaxHelloBytes || p[0] != 22 {
		return d
	}
	if len(p) < 5 {
		d.Reason = "CLIENTHELLO_INCOMPLETE"
		d.Detail = "TLS record header incomplete"
		return d
	}
	if p[1] != 3 || p[2] < 1 || p[2] > 3 {
		return d
	}
	d.RecordBytes = 5 + int(binary.BigEndian.Uint16(p[3:5]))
	if d.RecordBytes > len(p) {
		d.Reason = "CLIENTHELLO_INCOMPLETE"
		d.Detail = "declared TLS record exceeds observed payload; no reassembly"
		return d
	}
	if d.RecordBytes <= 5 || p[5] != 1 {
		return d
	}
	if d.RecordBytes < 9 {
		d.Reason = "CLIENTHELLO_INCOMPLETE"
		d.Detail = "ClientHello header spans records"
		return d
	}
	d.HandshakeBytes = 9 + (int(p[6])<<16 | int(p[7])<<8 | int(p[8]))
	if d.HandshakeBytes > d.RecordBytes {
		d.Reason = "CLIENTHELLO_INCOMPLETE"
		d.Detail = "ClientHello spans TLS records; no reassembly"
		return d
	}
	if start, n, ok := tlsSNI(p); ok {
		d.Domain = strings.Clone(string(p[start : start+n]))
		d.Detail = "complete ClientHello with observed outer SNI"
		return d
	}
	// Only report missing SNI for a structurally valid complete ClientHello.
	end := d.RecordBytes
	if end < 44 || d.HandshakeBytes != end || p[9] != 3 || p[10] < 1 || p[10] > 3 || p[43] > 32 {
		return d
	}
	i := 44 + int(p[43])
	if i+2 > end {
		return d
	}
	n := int(binary.BigEndian.Uint16(p[i:]))
	i += 2
	if n < 2 || n%2 != 0 || i+n+1 > end {
		return d
	}
	i += n
	n = int(p[i])
	i++
	if n < 1 || i+n > end {
		return d
	}
	i += n
	if i == end {
		d.Reason = "SNI_NOT_FOUND"
		d.Detail = "complete ClientHello without extensions"
		return d
	}
	if i+2 > end {
		return d
	}
	n = int(binary.BigEndian.Uint16(p[i:]))
	i += 2
	if i+n != end {
		return d
	}
	for i < end {
		if i+4 > end {
			return d
		}
		kind := binary.BigEndian.Uint16(p[i:])
		n = int(binary.BigEndian.Uint16(p[i+2:]))
		i += 4
		if i+n > end || kind == 0 {
			return d
		}
		i += n
	}
	d.Reason = "SNI_NOT_FOUND"
	d.Detail = "complete ClientHello has no server_name extension"
	return d
}

// Packet headers only, never payload or absolute sequence numbers.
func DescribeSentPacket(p, original []byte) SentPacket {
	v := SentPacket{Length: len(p)}
	if len(p) >= 20 {
		v.TTL = p[8]
		v.Protocol = p[9]
	}
	if len(p) >= 40 && len(original) >= 40 && p[0] == 0x45 && original[0] == 0x45 && p[9] == 6 {
		v.SequenceOffset = int32(binary.BigEndian.Uint32(p[24:]) - binary.BigEndian.Uint32(original[24:]))
		v.Flags = p[33]
		v.ACKOffset = int32(binary.BigEndian.Uint32(p[28:]) - binary.BigEndian.Uint32(original[28:]))
		stamp, has, md5 := packetTCPOptions(p)
		before, old, _ := packetTCPOptions(original)
		v.TimestampPresent = has
		v.MD5Present = md5
		if has && old {
			v.TimestampDelta = int32(stamp - before)
		}
	}
	return v
}

func packetTCPOptions(p []byte) (stamp uint32, has, md5 bool) {
	if len(p) < 40 {
		return
	}
	end := 20 + int(p[32]>>4)*4
	if end > len(p) {
		return
	}
	for i := 40; i < end; {
		if p[i] == 0 {
			break
		}
		if p[i] == 1 {
			i++
			continue
		}
		if i+1 >= end || p[i+1] < 2 || i+int(p[i+1]) > end {
			break
		}
		if p[i] == 8 && p[i+1] == 10 {
			stamp = binary.BigEndian.Uint32(p[i+2:])
			has = true
		}
		if p[i] == 19 && p[i+1] == 18 {
			md5 = true
		}
		i += int(p[i+1])
	}
	return
}
