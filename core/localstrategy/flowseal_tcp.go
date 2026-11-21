package localstrategy

// Own typed packet recipes. Public upstream parameters are data; no upstream
// binary/fake payload is embedded and no command line can be executed here.
import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

const NativeTCPPacketLimit = 64

type NativeFakeModel struct {
	Kind         string `json:"kind"`
	Host         string `json:"host,omitempty"`
	DuplicateSID bool   `json:"duplicate_sid,omitempty"`
	Randomize    bool   `json:"randomize,omitempty"`
}
type NativeTCPPlan struct {
	Mode            string            `json:"mode"`
	Repeats         uint8             `json:"repeats"`
	Fooling         string            `json:"fooling,omitempty"`
	BadSequence     int32             `json:"bad_sequence"`
	BadACK          int32             `json:"bad_ack"`
	TimestampDelta  int32             `json:"timestamp_delta"`
	Models          []NativeFakeModel `json:"models,omitempty"`
	Markers         []string          `json:"markers,omitempty"`
	Host            string            `json:"host,omitempty"`
	AlternateOrder  bool              `json:"alternate_order,omitempty"`
	ZeroIPID        bool              `json:"zero_ip_id,omitempty"`
	SequenceOverlap uint16            `json:"sequence_overlap,omitempty"`
}

func (p NativeTCPPlan) validate() error {
	switch p.Mode {
	case "fake", "fake,multisplit", "multisplit", "fake,multidisorder", "multidisorder", "fake,fakedsplit", "fakedsplit", "fake,hostfakesplit", "hostfakesplit", "fake,fakeddisorder", "fakeddisorder", "syndata", "syndata,multidisorder":
	default:
		return errors.New("unknown native TCP recipe")
	}
	if p.Repeats < 1 || p.Repeats > 16 || len(p.Models) > 3 || len(p.Markers) > 3 || p.SequenceOverlap > 1024 || len(p.Host) > 253 {
		return errors.New("native TCP recipe limits")
	}
	switch p.Fooling {
	case "", "ts", "md5sig", "ts,md5sig", "badseq":
	default:
		return errors.New("unknown native fooling")
	}
	for _, m := range p.Models {
		if len(m.Host) > 253 || strings.ContainsAny(m.Host, "\r\n\x00") {
			return errors.New("invalid fake SNI")
		}
		switch m.Kind {
		case "tls", "stun", "stun2", "zeros4":
		default:
			return errors.New("unknown fake model")
		}
	}
	for _, v := range p.Markers {
		switch v {
		case "1", "2", "midsld", "sniext+1", "sni+1":
		default:
			return errors.New("unknown native split marker")
		}
	}
	return nil
}
func compileNativeTCP(r CatalogRule) ([]Action, string) {
	get := func(k string) string {
		v := r.Options[k]
		if len(v) > 0 {
			return v[len(v)-1]
		}
		return ""
	}
	p := NativeTCPPlan{Mode: get("dpi-desync"), Repeats: 1, BadSequence: -10000, BadACK: -66000, TimestampDelta: -600000, Fooling: get("dpi-desync-fooling"), ZeroIPID: get("ip-id") == "zero"}
	if v := get("dpi-desync-repeats"); v != "" {
		n, e := strconv.ParseUint(v, 10, 8)
		if e != nil || n < 1 || n > 16 {
			return nil, "REPEATS_OUTSIDE_1_16"
		}
		p.Repeats = uint8(n)
	}
	if v := get("dpi-desync-badseq-increment"); v != "" {
		n, e := strconv.ParseInt(v, 10, 32)
		if e != nil {
			return nil, "INVALID_BADSEQ"
		}
		p.BadSequence = int32(n)
	}
	if v := get("dpi-desync-split-seqovl"); v != "" {
		n, e := strconv.ParseUint(v, 10, 16)
		if e != nil || n > 1024 {
			return nil, "INVALID_SEQOVL"
		}
		p.SequenceOverlap = uint16(n)
	}
	if v := get("dpi-desync-split-pos"); v != "" {
		p.Markers = strings.Split(v, ",")
	} else {
		p.Markers = nil
	}
	for _, v := range strings.Split(get("dpi-desync-hostfakesplit-mod"), ",") {
		if strings.HasPrefix(v, "host=") {
			p.Host = strings.TrimPrefix(v, "host=")
		}
		if v == "altorder=1" {
			p.AlternateOrder = true
		}
	}
	if v := get("dpi-desync-fakedsplit-pattern"); v != "" && v != "0x00" {
		return nil, "UNSUPPORTED_NATIVE_PATTERN"
	}
	for _, v := range r.Options["dpi-desync-fake-tls"] {
		name := strings.TrimPrefix(strings.ToLower(filepath.Base(strings.ReplaceAll(v, `\`, "/"))), "%bin%")
		m := NativeFakeModel{Kind: "tls", Host: "www.google.com"}
		switch {
		case name == "^!" || name == "!":
		case strings.HasPrefix(name, "0x"):
			b, e := hex.DecodeString(name[2:])
			if e != nil || len(b) != 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
				return nil, "UNKNOWN_RAW_FAKE"
			}
			m.Kind = "zeros4"
			m.Host = ""
		case name == "stun.bin" || name == "stun2.bin":
			m.Kind = strings.TrimSuffix(name, ".bin")
			m.Host = ""
		case strings.Contains(name, "www_google_com"):
			m.Host = "www.google.com"
		case strings.Contains(name, "www_sferum_ru"):
			m.Host = "www.sferum.ru"
		case strings.Contains(name, "4pda_to"):
			m.Host = "4pda.to"
		case strings.Contains(name, "sochi_park"):
			m.Host = "sochi-park.ru"
		default:
			return nil, "UNKNOWN_FAKE_TEMPLATE"
		}
		p.Models = append(p.Models, m)
	}
	if len(p.Models) == 0 && strings.HasPrefix(p.Mode, "fake") {
		p.Models = []NativeFakeModel{{Kind: "tls", Host: "www.google.com"}}
	}
	if len(p.Models) > 0 {
		m := &p.Models[len(p.Models)-1]
		for _, v := range strings.Split(get("dpi-desync-fake-tls-mod"), ",") {
			switch {
			case v == "rnd":
				m.Randomize = true
			case v == "dupsid":
				m.DuplicateSID = true
			case strings.HasPrefix(v, "sni="):
				m.Host = strings.TrimPrefix(v, "sni=")
			}
		}
	}
	if e := p.validate(); e != nil {
		return nil, "NATIVE_TCP_RECIPE_INVALID"
	}
	return []Action{{Kind: "native-tcp443", Native: &p}}, ""
}
