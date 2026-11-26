package clubhealth

import "time"

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

func (e Diagnostic) validClubLink() bool {
	if e.ClubLink.IsZero() {
		return e.Component != "CLUB_LINK"
	}
	if !e.ClubLink.Valid(e.At) || e.Component != "CLUB_LINK" || e.Observer != "PASSIVE_TCP_TABLE" ||
		e.App != "langameservice.exe" || !e.ProcessVerified || e.PID == 0 || e.Birth == 0 ||
		e.Incident != e.ClubLink.LinkID || e.Code != e.ClubLink.Event || e.Occurrences != 0 ||
		e.NativeCode != 0 || e.ProviderState != 0 || e.Operation != "" || e.EventID != 0 ||
		e.RecordID != 0 || e.Port != 0 || e.Lost != 0 {
		return false
	}
	return e.Code == "CONNECTION_LOST" && e.State == "failed" ||
		e.Code == "CONNECTION_RESTORED" && e.State == "recovered"
}
