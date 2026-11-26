package clubhealth

import (
	"strconv"
	"strings"
	"time"
)

// ClubLink describes an observed TCP transition, not application availability or
// its cause. It stays comparable because Diagnostic is also a repeat-map key.
// PeerID is random and local to the reporting service session; no address,
// service port, packet contents or error message crosses the device boundary.
type ClubLink struct {
	Kind              string    `json:"kind"`
	LinkID            string    `json:"link_id"`
	PeerID            string    `json:"peer_id"`
	Protocol          string    `json:"protocol"`
	Event             string    `json:"event"`
	Previous          string    `json:"previous"`
	Current           string    `json:"current"`
	LastEstablishedAt time.Time `json:"last_established_at"`
}

func (v ClubLink) IsZero() bool { return v == (ClubLink{}) }

func (v ClubLink) Valid(at time.Time) bool {
	if v.Kind != "LANGAME" || !eventID.MatchString(v.LinkID) || !eventID.MatchString(v.PeerID) ||
		(v.Protocol != "TCP4" && v.Protocol != "TCP6") || v.LastEstablishedAt.IsZero() ||
		v.LastEstablishedAt.After(at) || v.LastEstablishedAt.Before(at.Add(-Retention)) {
		return false
	}
	switch v.Event {
	case "CONNECTION_LOST":
		return v.Previous == "ESTABLISHED" && v.Current == "ABSENT"
	case "CONNECTION_RESTORED":
		return v.Previous == "ABSENT" && v.Current == "ESTABLISHED" && v.LastEstablishedAt.Equal(at)
	}
	return false
}

// EffectiveClubLink reads either representation without changing the signed
// event. Operation is an envelope understood by the pre-ClubLink journal codec:
// CL1_{4|6}_{32 uppercase peer hex}_{positive Unix nanoseconds}.
func (e Diagnostic) EffectiveClubLink() (ClubLink, bool) {
	if e.Component != "CLUB_LINK" {
		return ClubLink{}, e.ClubLink.IsZero() && !strings.HasPrefix(e.Operation, "CL1_")
	}
	if !eventID.MatchString(e.ID) || !eventID.MatchString(e.Session) || !eventID.MatchString(e.Incident) ||
		!label.MatchString(e.PC) || !buildID.MatchString(e.Version) || !buildID.MatchString(e.Source) || e.ServicePID == 0 ||
		e.At.IsZero() || e.Observer != "PASSIVE_TCP_TABLE" ||
		e.App != "langameservice.exe" || !e.ProcessVerified || e.PID == 0 || e.Birth == 0 ||
		e.Occurrences != 0 || !e.LastAt.IsZero() || e.NativeCode != 0 || e.ProviderState != 0 || e.EventID != 0 ||
		e.RecordID != 0 || e.Port != 0 || e.Lost != 0 {
		return ClubLink{}, false
	}
	if !(e.Code == "CONNECTION_LOST" && e.State == "failed" || e.Code == "CONNECTION_RESTORED" && e.State == "recovered") {
		return ClubLink{}, false
	}
	v := e.ClubLink
	if e.Operation != "" {
		shadow, ok := e.decodeClubLinkShadow()
		if !ok || !v.IsZero() && !sameClubLink(v, shadow) {
			return ClubLink{}, false
		}
		v = shadow
	}
	if !v.Valid(e.At) || v.LinkID != e.Incident || v.Event != e.Code {
		return ClubLink{}, false
	}
	v.LastEstablishedAt = v.LastEstablishedAt.UTC()
	return v, true
}

func sameClubLink(a, b ClubLink) bool {
	lastA, lastB := a.LastEstablishedAt, b.LastEstablishedAt
	a.LastEstablishedAt, b.LastEstablishedAt = time.Time{}, time.Time{}
	return a == b && lastA.Equal(lastB)
}

func (e Diagnostic) decodeClubLinkShadow() (ClubLink, bool) {
	if len(e.Operation) > 64 {
		return ClubLink{}, false
	}
	parts := strings.Split(e.Operation, "_")
	if len(parts) != 4 || parts[0] != "CL1" || (parts[1] != "4" && parts[1] != "6") ||
		len(parts[2]) != 32 || strings.ToUpper(parts[2]) != parts[2] || !eventID.MatchString(strings.ToLower(parts[2])) {
		return ClubLink{}, false
	}
	nanos, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || nanos <= 0 || strconv.FormatInt(nanos, 10) != parts[3] {
		return ClubLink{}, false
	}
	v := ClubLink{Kind: "LANGAME", LinkID: e.Incident, PeerID: strings.ToLower(parts[2]), Protocol: "TCP" + parts[1],
		Event: e.Code, Previous: "ESTABLISHED", Current: "ABSENT", LastEstablishedAt: time.Unix(0, nanos).UTC()}
	if e.Code == "CONNECTION_RESTORED" {
		v.Previous, v.Current = "ABSENT", "ESTABLISHED"
	}
	return v, true
}

// WithClubLinkShadow adds only the data absent from the old journal's metadata
// allowlist. Producers call this before persisting or signing a new observation.
func (e Diagnostic) WithClubLinkShadow() (Diagnostic, bool) {
	if e.ClubLink.IsZero() || e.Operation != "" {
		return e, false
	}
	v, ok := e.EffectiveClubLink()
	if !ok {
		return e, false
	}
	nanos := v.LastEstablishedAt.UnixNano()
	if nanos <= 0 || !time.Unix(0, nanos).Equal(v.LastEstablishedAt) {
		return e, false
	}
	e.Operation = "CL1_" + strings.TrimPrefix(v.Protocol, "TCP") + "_" + strings.ToUpper(v.PeerID) + "_" + strconv.FormatInt(nanos, 10)
	return e, len(e.Operation) <= 64
}

// CanonicalClubLink returns a storage-only copy. Calling this before checking a
// batch proof would change its audience; the wire batch and ACK must stay intact.
func (e Diagnostic) CanonicalClubLink() (Diagnostic, bool) {
	v, ok := e.EffectiveClubLink()
	if !ok {
		return e, false
	}
	if e.Component == "CLUB_LINK" {
		e.ClubLink, e.Operation = v, ""
	}
	return e, true
}

func (e Diagnostic) validClubLink() bool {
	_, ok := e.EffectiveClubLink()
	return ok
}
