package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/jackc/pgx/v5"
)

// FleetRelayState is used by the root-only fleet tool. Hashes never go to clients.
type FleetRelayState struct {
	Healthy       bool                     `json:"healthy"`
	HeartbeatAt   *time.Time               `json:"heartbeat_at,omitempty"`
	Exists        bool                     `json:"exists"`
	Node          optimizer.RelayCandidate `json:"node"`
	HeartbeatHash []byte                   `json:"heartbeat_hash,omitempty"`
}

func (s *Store) FleetRelay(ctx context.Context, id string) (FleetRelayState, error) {
	var state FleetRelayState
	var raw []byte
	err := s.DB.QueryRow(ctx, "SELECT metadata,heartbeat_token_hash,healthy,heartbeat_at FROM relay_nodes WHERE id=$1", id).Scan(&raw, &state.HeartbeatHash, &state.Healthy, &state.HeartbeatAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	state.Exists = true
	err = json.Unmarshal(raw, &state.Node)
	return state, err
}

// Compare-and-publish is atomic. Rollback means a NEW signed config containing
// the previous relay row, never restoration of DB/security records or versions.
func (s *Store) ChangeFleetRelay(ctx context.Context, id, expectedAddress string, next FleetRelayState, kid string, key []byte, public map[string]string, expectedHash []byte) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); err != nil {
		return err
	}
	var raw, hash []byte
	err = tx.QueryRow(ctx, "SELECT metadata,heartbeat_token_hash FROM relay_nodes WHERE id=$1 FOR UPDATE", id).Scan(&raw, &hash)
	if err == nil {
		var old optimizer.RelayCandidate
		if json.Unmarshal(raw, &old) != nil || old.Address != expectedAddress || !bytes.Equal(hash, expectedHash) {
			return errors.New("RELAY_REGISTRY_CONCURRENT_CHANGE")
		}
	} else if !errors.Is(err, pgx.ErrNoRows) || expectedAddress != "" {
		return errors.New("RELAY_REGISTRY_CONCURRENT_CHANGE")
	}
	if next.Exists {
		if next.Node.ID != id {
			return errors.New("RELAY_REGISTRY_ID_MISMATCH")
		}
		raw, err = json.Marshal(next.Node)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO relay_nodes(id,metadata,heartbeat_token_hash) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata,heartbeat_token_hash=excluded.heartbeat_token_hash,healthy=false,heartbeat_at=NULL", id, raw, next.HeartbeatHash)
	} else {
		_, err = tx.Exec(ctx, "DELETE FROM relay_nodes WHERE id=$1", id)
	}
	if err != nil {
		return err
	}
	rows, err := readRelays(ctx, tx)
	if err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM relay_nodes").Scan(&count); err != nil {
		return err
	}
	if count != len(rows) || count > 32 {
		return errors.New("RELAY_REGISTRY_CAPACITY_NO_TRUNCATION")
	}
	if _, err = publishConfigTx(ctx, tx, kid, key, public); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
