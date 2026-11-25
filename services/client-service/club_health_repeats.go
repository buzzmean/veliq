package clientservice

import (
	"github.com/buzzmean/veliq/core/clubhealth"
	"time"
)

const diagnosticRepeatKeys = 64
const diagnosticWriteInterval = 10 * time.Second

type diagnosticRepeat struct {
	event clubhealth.Diagnostic
	dirty bool
}

// Короткая блокировка защищает только64счётчика. Диск, сеть и обычная очередь
// здесь не используются, поэтому шторм не вытесняет lifecycle/recovery.
func (d *persistentDiagnostics) offerRepeated(e clubhealth.Diagnostic) {
	d.repeatMu.Lock()
	defer d.repeatMu.Unlock()
	if d.repeats == nil {
		d.repeats = make(map[clubhealth.Diagnostic]diagnosticRepeat)
	}
	key := e.RepeatKey()
	if row, ok := d.repeats[key]; ok && e.At.Before(row.event.At.Add(clubhealth.Retention)) {
		if row.event.Occurrences < 1<<63-1 {
			row.event.Occurrences++
		} else {
			d.dropped.Add(1)
		}
		if e.At.After(row.event.LastAt) {
			row.event.LastAt = e.At
		}
		row.dirty = true
		d.repeats[key] = row
		return
	}
	if _, ok := d.repeats[key]; !ok && len(d.repeats) >= diagnosticRepeatKeys {
		// Неактивный класс можно завершить только после его переноса в журнал.
		for k, row := range d.repeats {
			if !row.dirty && !e.At.Before(row.event.LastAt.Add(time.Hour)) {
				delete(d.repeats, k)
			}
		}
		if len(d.repeats) >= diagnosticRepeatKeys {
			d.dropped.Add(1)
			return
		}
	}
	e.Occurrences, e.LastAt = 1, e.At
	d.repeats[key] = diagnosticRepeat{event: e, dirty: true}
}
func (d *persistentDiagnostics) takeRepeats() []clubhealth.Diagnostic {
	d.repeatMu.Lock()
	defer d.repeatMu.Unlock()
	out := make([]clubhealth.Diagnostic, 0, len(d.repeats))
	for key, row := range d.repeats {
		if row.dirty {
			out = append(out, row.event)
			row.dirty = false
			d.repeats[key] = row
		}
	}
	return out
}
func (d *persistentDiagnostics) resetRepeats() {
	d.repeatMu.Lock()
	defer d.repeatMu.Unlock()
	d.repeats = nil
}
