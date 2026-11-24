package controlclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/buzzmean/veliq/core/deviceinfo"
	"github.com/buzzmean/veliq/core/security"
)

func (c *Client) SupportsDeviceMetadata(ctx context.Context) (bool, error) {
	raw, err := c.request(ctx, "GET", "/api/v1/device/details", nil, "")
	if err != nil {
		return false, err
	}
	var out struct {
		Supported bool `json:"supported"`
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return false, err
	}
	return out.Supported, nil
}

// DeviceMetadata обновляет только сведения об этом устройстве.
func (c *Client) DeviceMetadata(ctx context.Context, details deviceinfo.Details) error {
	if !details.Valid() || len(c.DeviceKey) != ed25519.PrivateKeySize {
		return errors.New("DEVICE_DETAILS_INVALID")
	}
	proof, err := security.NewProof(c.DeviceID, details.Audience(), c.DeviceKey, time.Now())
	if err != nil {
		return err
	}
	_, err = c.request(ctx, "POST", "/api/v1/device/details", deviceinfo.Request{Details: details, Proof: proof}, "")
	return err
}
