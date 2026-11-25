package clubhealth

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

type JournalRow struct {
	Event Diagnostic `json:"event"`
	Acked bool       `json:"acked,omitempty"`
}
type Journal struct {
	Open        bool         `json:"open"`
	Transitions Transitions  `json:"transitions"`
	Format      int          `json:"format"`
	Device      string       `json:"device"`
	Rows        []JournalRow `json:"rows"`
	// Сохранённый backlog прежней версии; общий файл по-прежнему не более4MiB.
	History []JournalRow `json:"history,omitempty"`
	Lost    uint64       `json:"lost"`
}

func LoadJournal(path, device string, now time.Time) Journal {
	j := Journal{Format: 1, Device: device}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return j
	}
	if err != nil {
		j.Lost++
		return j
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > JournalBytes {
		j.Lost++
		return j
	}
	b, err := io.ReadAll(io.LimitReader(f, JournalBytes+1))
	var old Journal
	if err != nil || len(b) > JournalBytes || json.Unmarshal(b, &old) != nil || old.Format != 1 || old.Device != device || len(old.Rows) > JournalEvents || len(old.History) > JournalEvents {
		j.Lost++
		return j
	}
	j.Lost, j.Open = old.Lost, old.Open
	if len(old.Transitions.Active) <= 64 && len(old.Transitions.Previous) <= 64 {
		j.Transitions = old.Transitions
	}
	seen := map[string]bool{}
	load := func(rows []JournalRow) []JournalRow {
		out := make([]JournalRow, 0, len(rows))
		for _, row := range rows {
			if row.Event.Valid(now) && !seen[row.Event.ID] {
				out = append(out, row)
				seen[row.Event.ID] = true
			} else if !row.Acked {
				j.Lost++
			}
		}
		return out
	}
	j.Rows = load(old.Rows)
	j.History = load(old.History)
	return j
}

// Перенос не меняет старыеID, данные илиACK и не обнуляет потери.
func (j *Journal) PreserveBacklog(version string) bool {
	if len(j.Rows) < JournalEvents/2 || len(j.History) != 0 {
		return false
	}
	for _, row := range j.Rows {
		if row.Event.Version != version {
			j.History, j.Rows = j.Rows, nil
			return true
		}
	}
	return false
}
func (j *Journal) Add(e Diagnostic, now time.Time) bool {
	if !e.Valid(now) {
		j.Lost++
		return false
	}
	for _, rows := range [][]JournalRow{j.Rows, j.History} {
		for i := range rows {
			if rows[i].Event.ID != e.ID {
				continue
			}
			changed, ok := DiagnosticUpdate(rows[i].Event, e)
			if !ok {
				j.Lost++
				return false
			}
			if changed {
				rows[i].Event = e
				rows[i].Acked = false
			}
			return changed
		}
	}
	j.Rows = append(j.Rows, JournalRow{Event: e})
	for len(j.Rows) > JournalEvents {
		j.drop(false)
	}
	return true
}
func (j *Journal) Trim(now time.Time) {
	trim := func(rows []JournalRow) []JournalRow {
		kept := rows[:0]
		for _, row := range rows {
			if row.Event.At.Before(now.Add(-Retention)) {
				if !row.Acked {
					j.Lost++
				}
			} else {
				kept = append(kept, row)
			}
		}
		return kept
	}
	j.Rows = trim(j.Rows)
	j.History = trim(j.History)
	for len(j.Rows) > JournalEvents {
		j.drop(false)
	}
	for len(j.History) > JournalEvents {
		j.drop(true)
	}
	for len(j.Rows)+len(j.History) > 0 {
		raw, _ := json.Marshal(j)
		if len(raw) <= JournalBytes {
			break
		}
		j.drop(true)
	}
}
func important(e Diagnostic) bool {
	return e.State != "observed" || e.Component == "SERVICE" || e.Component == "JOURNAL"
}

// Сначала убирается доставленный шум; жизненный цикл и восстановление — последними.
func (j *Journal) drop(history bool) {
	queues := []*[]JournalRow{&j.Rows}
	if history {
		queues = []*[]JournalRow{&j.History, &j.Rows}
	}
	bestRank := 5
	var selected *[]JournalRow
	index := 0
	for _, q := range queues {
		for i, row := range *q {
			rank := 0
			if important(row.Event) {
				rank += 2
			}
			if !row.Acked {
				rank++
			}
			if rank < bestRank {
				bestRank, selected, index = rank, q, i
			}
		}
	}
	if selected == nil {
		return
	}
	rows := *selected
	if !rows[index].Acked {
		j.Lost++
	}
	copy(rows[index:], rows[index+1:])
	rows[len(rows)-1] = JournalRow{}
	*selected = rows[:len(rows)-1]
}
func (j *Journal) Save(write func([]byte) error) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(b) > JournalBytes {
		return errors.New("journal capacity exceeded")
	}
	return write(b)
}

// Половина пакета зарезервирована для backlog, когда есть новые наблюдения.
func (j *Journal) Batch() Batch {
	b := Batch{Protocol: 1, Events: []Diagnostic{}}
	add := func(rows []JournalRow, critical bool, limit int) {
		for _, row := range rows {
			if len(b.Events) >= limit {
				return
			}
			if !row.Acked && important(row.Event) == critical {
				b.Events = append(b.Events, row.Event)
			}
		}
	}
	add(j.Rows, true, MaxEvents)
	add(j.History, true, MaxEvents)
	activeEnd := min(MaxEvents, len(b.Events)+MaxEvents/2)
	add(j.Rows, false, activeEnd)
	add(j.History, false, MaxEvents)
	// Если backlog не занял резерв, оставшиеся активные записи тоже доставляются.
	if len(b.Events) < MaxEvents {
		seen := map[string]bool{}
		for _, e := range b.Events {
			seen[e.ID] = true
		}
		for _, row := range j.Rows {
			if len(b.Events) == MaxEvents {
				break
			}
			if !row.Acked && !seen[row.Event.ID] {
				b.Events = append(b.Events, row.Event)
				seen[row.Event.ID] = true
			}
		}
	}
	return b
}
func (j *Journal) Ack(b Batch, receipt Receipt) bool {
	if !receipt.Accepts(b) {
		return false
	}
	sent := map[string]Diagnostic{}
	for _, e := range b.Events {
		sent[e.ID] = e
	}
	changed := false
	for _, rows := range [][]JournalRow{j.Rows, j.History} {
		for i := range rows {
			e, ok := sent[rows[i].Event.ID]
			//ACK старого счётчика не подтверждает повтор, возникший после отправки.
			if ok && rows[i].Event == e && !rows[i].Acked {
				rows[i].Acked = true
				changed = true
			}
		}
	}
	return changed
}
func (j *Journal) Snapshot() Journal {
	return Journal{Format: j.Format, Device: j.Device, Rows: append([]JournalRow(nil), j.Rows...), History: append([]JournalRow(nil), j.History...)}
}
