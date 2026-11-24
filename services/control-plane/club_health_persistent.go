package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/buzzmean/neexitlag/core/clubhealth"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var errDiagnosticProof = errors.New("DIAGNOSTIC_PROOF_REJECTED")
var errDiagnosticOwner = errors.New("DIAGNOSTIC_OWNER_REQUIRED")

func (a *API) persistentClubHealth(w http.ResponseWriter, r *http.Request) {
	var q clubhealth.PersistentRequest
	if body(r, &q) != nil || q.Batch.Validate(time.Now()) != nil || q.Proof.RelayID != q.Batch.Audience() {
		a.fail(w, 400, "DIAGNOSTIC_BATCH_INVALID")
		return
	}
	d, err := a.Store.Device(r.Context(), q.Proof.DeviceID)
	key, keyErr := security.DecodePublicKey(d.PublicKey)
	if err != nil || d.Revoked || keyErr != nil || q.Proof.Verify(key, time.Now()) != nil {
		a.fail(w, 401, "DIAGNOSTIC_PROOF_INVALID")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	err = a.Store.RecordPersistentDiagnostics(ctx, q)
	switch {
	case errors.Is(err, errDiagnosticProof):
		a.fail(w, 401, "DIAGNOSTIC_PROOF_REJECTED")
	case errors.Is(err, errDiagnosticOwner):
		a.fail(w, 403, "DIAGNOSTIC_OWNER_REQUIRED")
	case err != nil:
		a.fail(w, 503, "DIAGNOSTIC_STORAGE_UNAVAILABLE")
	default:
		respond(w, 200, clubhealth.Receipt{Protocol: 1, Committed: true, Digest: q.Batch.Audience()})
	}
}

// Ownership comes from the active subscription/slot, never the claimed PC name.
// FOR UPDATE on the device is also used by activation/revocation and serializes
// duplicate ingestion and quota pruning for this identity.
func (s *Store) RecordPersistentDiagnostics(ctx context.Context, q clubhealth.PersistentRequest) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = consumeDeviceProof(ctx, tx, q.Proof); err != nil {
		var pgerr *pgconn.PgError
		if errors.Is(err, pgx.ErrNoRows) || err.Error() == "device revoked" || errors.As(err, &pgerr) && pgerr.Code == "23505" {
			return errDiagnosticProof
		}
		return err
	}
	var owner string
	// Старые клубные активации имеют место подписки без account_device_bindings.
	// Принимаем только единственного подтверждённого владельца действующих мест.
	err = tx.QueryRow(ctx, diagnosticOwnerSQL, q.Proof.DeviceID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return errDiagnosticOwner
	}
	if err != nil {
		return err
	}
	var previous *time.Time
	var gapID string
	err = tx.QueryRow(ctx, "SELECT last_seen,md5(device_id||':'||last_seen::text) FROM club_health_persistent_devices WHERE device_id=$1 AND account_id=$2", q.Proof.DeviceID, owner).Scan(&previous, &gapID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	pc, version, source := "", "", ""
	if len(q.Batch.Events) > 0 {
		last := q.Batch.Events[len(q.Batch.Events)-1]
		pc, version, source = last.PC, last.Version, last.Source
	}
	if pc == "" {
		err = tx.QueryRow(ctx, "SELECT pc,software_version,source FROM club_health_persistent_devices WHERE device_id=$1 AND account_id=$2", q.Proof.DeviceID, owner).Scan(&pc, &version, &source)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO club_health_persistent_devices(device_id,account_id,pc,software_version,source)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT(device_id) DO UPDATE SET account_id=excluded.account_id,last_seen=now(),missing_since=NULL,
		pc=CASE WHEN excluded.pc<>'' THEN excluded.pc ELSE club_health_persistent_devices.pc END,
		software_version=CASE WHEN excluded.pc<>'' THEN excluded.software_version ELSE club_health_persistent_devices.software_version END,
		source=CASE WHEN excluded.pc<>'' THEN excluded.source ELSE club_health_persistent_devices.source END`, q.Proof.DeviceID, owner, pc, version, source)
	if err != nil {
		return err
	}
	for _, e := range q.Batch.Events {
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO club_health_persistent_events(device_id,event_id,account_id,observed_at,summary)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT(device_id,event_id) DO NOTHING`, q.Proof.DeviceID, e.ID, owner, e.At, raw)
		if err != nil {
			return err
		}
	}

	if previous != nil && time.Since(*previous) > clubhealth.MissingAfter {
		begin := clubhealth.Diagnostic{ID: gapID, Incident: gapID, PC: pc, Version: version, Source: source,
			At: previous.Add(clubhealth.MissingAfter), Component: "HEARTBEAT", Observer: "SERVER_RECEIPT",
			State: "failed", Code: "REPORTING_GAP_CAUSE_UNKNOWN"}
		end := begin
		end.ID, _ = security.NewID()
		end.At = time.Now().UTC()
		end.State = "recovered"
		end.Code = "REPORTING_RESUMED_CAUSE_UNKNOWN"
		for _, e := range []clubhealth.Diagnostic{begin, end} {
			raw, _ := json.Marshal(e)
			_, err = tx.Exec(ctx, `INSERT INTO club_health_persistent_events(device_id,event_id,account_id,observed_at,summary)
				VALUES($1,$2,$3,$4,$5) ON CONFLICT(device_id,event_id) DO NOTHING`, q.Proof.DeviceID, e.ID, owner, e.At, raw)
			if err != nil {
				return err
			}
		}
	}
	// A receipt acknowledges durable processing; bounded retention may then
	// evict oldest records, with a visible monotonically increasing counter.
	if err = pruneDiagnosticDevice(ctx, tx, q.Proof.DeviceID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const diagnosticOwnerSQL = `WITH owners AS (
 SELECT DISTINCT sub.account_id FROM activation_slots sl
 JOIN activation_codes c ON c.id=sl.code_id JOIN subscriptions sub ON sub.id=c.subscription_id
 JOIN accounts a ON a.id=sub.account_id
 WHERE sl.device_id=$1 AND NOT sl.disabled AND NOT c.revoked AND NOT a.disabled
), unique_owner AS (SELECT min(account_id) AS account_id FROM owners HAVING count(*)=1)
SELECT account_id FROM unique_owner o WHERE NOT EXISTS(
 SELECT 1 FROM account_device_bindings b JOIN subscriptions s ON s.id=b.subscription_id
 WHERE b.device_id=$1 AND s.account_id<>o.account_id)`

func pruneDiagnosticDevice(ctx context.Context, tx pgx.Tx, device string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM club_health_persistent_events WHERE device_id=$1 AND event_id IN(
		SELECT event_id FROM club_health_persistent_events WHERE device_id=$1
		ORDER BY observed_at DESC,event_id DESC OFFSET $2)`, device, clubhealth.ServerDeviceEvents)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		_, err = tx.Exec(ctx, "UPDATE club_health_persistent_devices SET discarded=discarded+$2 WHERE device_id=$1", device, tag.RowsAffected())
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *API) accountDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	account, _, ok := a.session(w, r)
	if !ok {
		return
	}
	pc := r.URL.Query().Get("pc")
	if len(pc) > 80 {
		a.fail(w, 400, "DIAGNOSTIC_PC_INVALID")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	out, err := a.Store.PersistentDiagnosticsView(ctx, account.ID, pc)
	if err != nil {
		a.fail(w, 503, "DIAGNOSTIC_VIEW_UNAVAILABLE")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/api/v1/account/diagnostics/view" {
		var view struct {
			Devices []struct {
				PC        string
				Version   string `json:"software_version"`
				State     string
				Discarded uint64
			}
			Events []struct{ Summary clubhealth.Diagnostic }
		}
		if json.Unmarshal(out, &view) != nil {
			a.fail(w, 503, "DIAGNOSTIC_VIEW_UNAVAILABLE")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = diagnosticView.Execute(w, view)
		return
	}
	respond(w, 200, out)
}

var diagnosticView = template.Must(template.New("diagnostics").Funcs(template.FuncMap{
	"hex": func(v uint32) string {
		if v == 0 {
			return ""
		}
		return fmt.Sprintf("0x%08X", v)
	},
}).Parse(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>VELIQ — диагностика компьютеров</title>
<h1>Диагностика компьютеров</h1>
<p>События за 14 дней. Сетевой отказ сам по себе не доказывает причину в VELIQ. Отсутствие отчётов означает пробел наблюдения.</p>
<form><label>Компьютер <input name="pc" maxlength="80" placeholder="PC13"></label><button>Показать</button></form>
<table><thead><tr><th>ПК</th><th>Версия VELIQ</th><th>Доставка</th><th>Удалено по лимиту</th></tr></thead><tbody>
{{range .Devices}}<tr><td>{{.PC}}</td><td>{{.Version}}</td><td>{{.State}}</td><td>{{.Discarded}}</td></tr>{{end}}</tbody></table>
<h2>Последние события</h2><table><thead><tr><th>UTC</th><th>ПК / версия</th><th>Источник</th><th>Состояние</th><th>Код</th><th>Процесс</th></tr></thead><tbody>
{{range .Events}}{{with .Summary}}<tr><td>{{.At}}</td><td>{{.PC}} / {{.Version}}</td><td>{{.Component}} / {{.Observer}}</td><td>{{.State}}</td>
<td>{{.Code}} {{hex .NativeCode}}; операция {{.Operation}}; состояние провайдера {{.ProviderState}}; EventID {{.EventID}}</td><td>{{.App}} PID {{.PID}}; поколение {{.Birth}}; подтверждено {{.ProcessVerified}}</td></tr>{{end}}{{end}}
</tbody></table><p>Показано до 300 событий. Журнал не содержит HTTPS-содержимое, ключи или коды активации.</p></html>`))

func (s *Store) PersistentDiagnosticsView(ctx context.Context, owner, pc string) (json.RawMessage, error) {
	var out json.RawMessage
	err := s.DB.QueryRow(ctx, `WITH owned AS (
		SELECT h.* FROM club_health_persistent_devices h JOIN devices d ON d.id=h.device_id
		WHERE h.account_id=$1 AND NOT d.revoked AND ($2='' OR h.pc=$2)
		AND EXISTS(SELECT 1 FROM activation_slots sl JOIN activation_codes c ON c.id=sl.code_id
		 JOIN subscriptions sub ON sub.id=c.subscription_id JOIN accounts a ON a.id=sub.account_id
		 WHERE sl.device_id=d.id AND NOT sl.disabled AND NOT c.revoked AND NOT a.disabled AND sub.account_id=$1)
		AND NOT EXISTS(SELECT 1 FROM activation_slots sl JOIN activation_codes c ON c.id=sl.code_id
		 JOIN subscriptions sub ON sub.id=c.subscription_id JOIN accounts a ON a.id=sub.account_id
		 WHERE sl.device_id=d.id AND NOT sl.disabled AND NOT c.revoked AND NOT a.disabled AND sub.account_id<>$1)
		AND NOT EXISTS(SELECT 1 FROM account_device_bindings b JOIN subscriptions sub ON sub.id=b.subscription_id
		 WHERE b.device_id=d.id AND sub.account_id<>$1))
		SELECT jsonb_build_object('retention_days',14,'max_events_per_device',8192,'attribution','unknown_without_independent_evidence',
		'devices',(SELECT coalesce(jsonb_agg(v),'[]') FROM(
		 SELECT pc,software_version,source,last_seen,discarded,
		  CASE WHEN last_seen<now()-interval '2 minutes' THEN 'reporting_gap_cause_unknown' ELSE 'reporting' END AS state
		 FROM owned ORDER BY pc LIMIT 500) v),
		'events',(SELECT coalesce(jsonb_agg(v),'[]') FROM(
		 SELECT e.summary,e.received_at FROM club_health_persistent_events e JOIN owned h ON h.device_id=e.device_id
		 WHERE e.account_id=$1 AND e.observed_at>=now()-interval '14 days'
		 ORDER BY e.received_at DESC,e.event_id DESC LIMIT 300) v))`, owner, pc).Scan(&out)
	return out, err
}

func (s *Store) PrunePersistentDiagnostics(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM club_health_persistent_events WHERE ctid IN (
		SELECT ctid FROM club_health_persistent_events WHERE observed_at<now()-interval '14 days' ORDER BY observed_at LIMIT 10000)`)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `DELETE FROM club_health_persistent_devices WHERE device_id IN (
	 SELECT h.device_id FROM club_health_persistent_devices h
	 WHERE h.last_seen<now()-interval '14 days' AND NOT EXISTS(
	  SELECT 1 FROM club_health_persistent_events e WHERE e.device_id=h.device_id)
	 ORDER BY h.last_seen LIMIT 1000)`)
	if err != nil {
		return err
	}
	rows, err := s.DB.Query(ctx, `SELECT device_id FROM club_health_persistent_devices
		WHERE missing_since IS NULL AND last_seen<now()-interval '2 minutes' ORDER BY last_seen LIMIT 100`)
	if err != nil {
		return err
	}
	var devices []string
	for rows.Next() {
		var device string
		if err := rows.Scan(&device); err != nil {
			rows.Close()
			return err
		}
		devices = append(devices, device)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, device := range devices {
		if err := s.recordDiagnosticGap(ctx, device); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) recordDiagnosticGap(ctx context.Context, device string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Тот же порядок блокировок, что у приёма: устройство, метаданные, события.
	// Занятое устройство проверит следующий проход, запись не задерживает upload.
	var locked string
	if err = tx.QueryRow(ctx, "SELECT id FROM devices WHERE id=$1 FOR UPDATE SKIP LOCKED", device).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `WITH gaps AS (
		UPDATE club_health_persistent_devices SET missing_since=last_seen+interval '2 minutes'
		WHERE device_id=$1 AND missing_since IS NULL AND last_seen<now()-interval '2 minutes' RETURNING *
	) INSERT INTO club_health_persistent_events(device_id,event_id,account_id,observed_at,summary)
	SELECT device_id,md5(device_id||':'||last_seen::text),account_id,missing_since,
		jsonb_build_object('id',md5(device_id||':'||last_seen::text),'incident',md5(device_id||':'||last_seen::text),
		'at',missing_since,'pc',pc,'version',software_version,'source',source,'component','HEARTBEAT','observer','SERVER_RECEIPT',
		'state','failed','code','REPORTING_GAP_CAUSE_UNKNOWN') FROM gaps
	ON CONFLICT(device_id,event_id) DO NOTHING`, device)
	if err != nil {
		return err
	}
	if err = pruneDiagnosticDevice(ctx, tx, device); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) RunPersistentDiagnosticsRetention(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		job, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.PrunePersistentDiagnostics(job); err != nil && ctx.Err() == nil {
			log.Print("DIAGNOSTIC_RETENTION_FAILED")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
