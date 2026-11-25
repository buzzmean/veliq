package controlclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/buzzmean/veliq/core/locallearning"
	"github.com/buzzmean/veliq/core/security"
	"time"
)

func (c *Client) LocalLearning(ctx context.Context, cmd locallearning.Command) ([]byte, error) {
	if len(c.DeviceKey) != ed25519.PrivateKeySize {
		return nil, errors.New("LOCAL_LEARNING_IDENTITY_REQUIRED")
	}
	proof, e := security.NewProof(c.DeviceID, locallearning.Audience(cmd), c.DeviceKey, time.Now())
	if e != nil {
		return nil, e
	}
	return c.request(ctx, "POST", "/api/v1/local/learning", locallearning.Request{Command: cmd, Proof: proof}, "")
}
