package traffic

import (
	"crypto/ed25519"
	"errors"
	"github.com/buzzmean/veliq/core/security"
	"time"
)

const Domain = "relay-traffic"

type Document struct {
	GeneratedAt, ExpiresAt time.Time
	Relays                 []MonthRow `json:"relays"`
	Scope                  string     `json:"scope"`
}

func Validate(keys map[string]ed25519.PublicKey, raw []byte, now time.Time) (Document, error) {
	var d Document
	if e := security.Verify(Domain, keys, raw, &d); e != nil {
		return d, e
	}
	if !d.ExpiresAt.After(now) || !d.ExpiresAt.After(d.GeneratedAt) || d.GeneratedAt.After(now.Add(30*time.Second)) || d.ExpiresAt.Sub(d.GeneratedAt) > 5*time.Minute || len(d.Relays) > 64 {
		return d, errors.New("TRAFFIC_SIGNED_DOCUMENT_INVALID_OR_EXPIRED")
	}
	for _, r := range d.Relays {
		if _, e := time.Parse("2006-01", r.Month); e != nil || len(r.Relay) == 0 || len(r.Relay) > 64 || r.Last.At.IsZero() || r.From.IsZero() || r.Last.At.After(d.GeneratedAt.Add(30*time.Second)) {
			return d, errors.New("TRAFFIC_SIGNED_ROW_INVALID")
		}
	}
	return d, nil
}
