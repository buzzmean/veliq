package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/buzzmean/veliq/core/deviceinfo"
	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var errDeviceDetailsProof = errors.New("DEVICE_DETAILS_PROOF_REJECTED")

func deviceConnection(lastSeen, heartbeat *time.Time, disabled bool, now time.Time) string {
	if disabled {
		return "disabled"
	}
	if lastSeen != nil && !lastSeen.After(now.Add(5*time.Second)) && now.Sub(*lastSeen) <= 3*time.Minute {
		return "online"
	}
	if heartbeat != nil && !heartbeat.After(now.Add(5*time.Second)) {
		return "offline"
	}
	return "unknown"
}

func (a *API) deviceDetails(w http.ResponseWriter, r *http.Request) {
	var q deviceinfo.Request
	if body(r, &q) != nil || !q.Details.Valid() || q.Proof.RelayID != q.Details.Audience() {
		a.fail(w, http.StatusBadRequest, "DEVICE_DETAILS_INVALID")
		return
	}
	d, err := a.Store.Device(r.Context(), q.Proof.DeviceID)
	if err != nil || d.Revoked {
		a.fail(w, http.StatusUnauthorized, "DEVICE_UNAVAILABLE")
		return
	}
	key, err := security.DecodePublicKey(d.PublicKey)
	if err != nil || q.Proof.Verify(key, time.Now()) != nil {
		a.fail(w, http.StatusUnauthorized, "DEVICE_PROOF_INVALID")
		return
	}
	if err = a.Store.RecordDeviceDetails(r.Context(), q.Proof, q.Details); err != nil {
		if errors.Is(err, errDeviceDetailsProof) {
			a.fail(w, http.StatusUnauthorized, "DEVICE_PROOF_REPLAY")
			return
		}
		a.fail(w, http.StatusServiceUnavailable, "DEVICE_DETAILS_UNAVAILABLE")
		return
	}
	respond(w, http.StatusOK, map[string]bool{"recorded": true})
}

func (s *Store) RecordDeviceDetails(ctx context.Context, proof security.Proof, details deviceinfo.Details) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = consumeDeviceProof(ctx, tx, proof); err != nil {
		var pgerr *pgconn.PgError
		if errors.Is(err, pgx.ErrNoRows) || err.Error() == "device revoked" || errors.As(err, &pgerr) && pgerr.Code == "23505" {
			return errDeviceDetailsProof
		}
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO device_details(device_id,computer_name,software_version,observed_at)
		VALUES($1,$2,$3,now()) ON CONFLICT(device_id) DO UPDATE SET computer_name=excluded.computer_name,
		software_version=excluded.software_version,observed_at=excluded.observed_at`, proof.DeviceID, details.ComputerName, details.Version)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validDeviceLabel(label string) bool {
	return utf8.ValidString(label) && utf8.RuneCountInString(label) <= 80 && !strings.ContainsFunc(label, unicode.IsControl)
}

func (s *Store) SetDeviceLabel(ctx context.Context, account Account, subscription, prefix, label string) error {
	if len(prefix) < 12 || len(prefix) > 64 || !validDeviceLabel(label) {
		return errors.New("DEVICE_LABEL_INVALID")
	}
	label = strings.TrimSpace(label)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT sl.machine_hash FROM activation_slots sl
		JOIN activation_codes c ON c.id=sl.code_id JOIN subscriptions sub ON sub.id=c.subscription_id
		WHERE sub.id=$1 AND sub.account_id=$2 AND NOT sl.disabled
		AND left(sl.machine_hash,$4)=$3 FOR UPDATE OF sl`, subscription, account.ID, prefix, len(prefix))
	if err != nil {
		return err
	}
	var machine string
	count := 0
	for rows.Next() {
		if err = rows.Scan(&machine); err != nil {
			rows.Close()
			return err
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("SEAT_NOT_FOUND")
	}
	if label == "" {
		_, err = tx.Exec(ctx, "DELETE FROM account_device_labels WHERE account_id=$1 AND machine_hash=$2", account.ID, machine)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO account_device_labels(account_id,machine_hash,label)
			VALUES($1,$2,$3) ON CONFLICT(account_id,machine_hash) DO UPDATE SET label=excluded.label,updated_at=now()`, account.ID, machine, label)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
