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
	Lost        uint64       `json:"lost"`
}

// Journal is owned by one worker. No disk I/O runs under a routing/IPC lock.
// It is both the rotated local history and the durable pending queue, so a
// crash cannot orphan a second queue file. At most 4 MiB + atomic replacement.
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
	if err != nil || len(b) > JournalBytes || json.Unmarshal(b, &old) != nil ||
		old.Format != 1 || old.Device != device || len(old.Rows) > JournalEvents {
		j.Lost++
		return j
	}
	j.Lost = old.Lost
	j.Open = old.Open
	if len(old.Transitions.Active) <= 64 && len(old.Transitions.Previous) <= 64 {
		j.Transitions = old.Transitions
	}
	for _, row := range old.Rows {
		if row.Event.Valid(now) {
			j.Rows = append(j.Rows, row)
		} else if !row.Acked {
			j.Lost++
		}
	}
	return j
}
func (j *Journal) Add(e Diagnostic, now time.Time) bool {
	if !e.Valid(now) {
		j.Lost++
		return false
	}
	for _, row := range j.Rows {
		if row.Event.ID == e.ID {
			return false
		}
	}
	j.Rows = append(j.Rows, JournalRow{Event: e})
	for len(j.Rows) > JournalEvents {
		j.drop()
	}
	return true
}
func (j *Journal) Trim(now time.Time) {
	kept := j.Rows[:0]
	for _, row := range j.Rows {
		if row.Event.At.Before(now.Add(-Retention)) {
			if !row.Acked {
				j.Lost++
			}
		} else {
			kept = append(kept, row)
		}
	}
	j.Rows = kept
	for len(j.Rows) > JournalEvents {
		j.drop()
	}
	// A bounded snapshot avoids unlimited disk growth even during a long outage.
	for len(j.Rows) > 0 {
		raw, _ := json.Marshal(j)
		if len(raw) <= JournalBytes {
			break
		}
		j.drop()
	}
}
func (j *Journal) drop() {
	if !j.Rows[0].Acked {
		j.Lost++
	}
	j.Rows = j.Rows[1:]
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
func (j *Journal) Batch() Batch {
	b := Batch{Protocol: 1, Events: []Diagnostic{}}
	for _, row := range j.Rows {
		if !row.Acked {
			b.Events = append(b.Events, row.Event)
		}
		if len(b.Events) == MaxEvents {
			break
		}
	}
	return b
}
func (j *Journal) Ack(b Batch, receipt Receipt) bool {
	if !receipt.Accepts(b) {
		return false
	}
	ids := map[string]bool{}
	changed := false
	for _, e := range b.Events {
		ids[e.ID] = true
	}
	for i := range j.Rows {
		if ids[j.Rows[i].Event.ID] && !j.Rows[i].Acked {
			j.Rows[i].Acked = true
			changed = true
		}
	}
	return changed
}
