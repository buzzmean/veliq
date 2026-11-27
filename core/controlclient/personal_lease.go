package controlclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/buzzmean/veliq/core/security"
)

type OptimizationLeasePolicy struct {
	Supported         bool `json:"supported"`
	Required          bool `json:"required"`
	TTLSeconds        int  `json:"ttl_seconds"`
	RenewAfterSeconds int  `json:"renew_after_seconds"`
}

type OptimizationLease struct {
	TTLSeconds        int        `json:"ttl_seconds"`
	RenewAfterSeconds int        `json:"renew_after_seconds"`
	Supported         bool       `json:"supported"`
	Required          bool       `json:"required"`
	Granted           bool       `json:"granted"`
	LeaseID           string     `json:"lease_id,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	ServerTime        time.Time  `json:"server_time"`
	Reason            string     `json:"reason,omitempty"`
}

func (c *Client) OptimizationLease(ctx context.Context, action, leaseID string) (OptimizationLease, error) {
	var out OptimizationLease
	if len(c.DeviceKey) != ed25519.PrivateKeySize {
		return out, errors.New("device identity required")
	}
	audience, err := security.PersonalOptimizationLeaseProofAudience(action, leaseID)
	if err != nil {
		return out, err
	}
	proof, err := security.NewProof(c.DeviceID, audience, c.DeviceKey, time.Now())
	if err != nil {
		return out, err
	}
	raw, err := c.request(ctx, "POST", "/api/v1/subscription/optimization-lease", struct {
		Proof   security.Proof `json:"proof"`
		Action  string         `json:"action"`
		LeaseID string         `json:"lease_id,omitempty"`
	}{proof, action, leaseID}, "")
	if err != nil {
		return out, err
	}
	if err := security.Parse(raw, &out); err != nil {
		return out, errors.New("invalid optimization lease response")
	}
	return out, nil
}
