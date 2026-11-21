package traffic

import (
	"errors"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Observation struct {
	Relay     string    `json:"relay"`
	Interface string    `json:"interface"`
	Boot      string    `json:"boot_epoch_hash"`
	BootAt    time.Time `json:"boot_at"`
	At        time.Time `json:"observed_at"`
	Counter   uint64    `json:"interface_tx_bytes"`
}
type MonthRow struct {
	ForecastValid bool        `json:"forecast_valid"`
	Relay         string      `json:"relay"`
	Month         string      `json:"month_utc"`
	Bytes         uint64      `json:"known_egress_bytes"`
	From          time.Time   `json:"known_from"`
	Last          Observation `json:"last_observation"`
	Partial       bool        `json:"partial_coverage"`
	Reason        string      `json:"coverage_reason"`
	Resets        uint64      `json:"counter_resets"`
	Limit         uint64      `json:"monthly_limit_bytes"`
	Forecast      uint64      `json:"forecast_bytes"`
	RateMbps      float64     `json:"last_interval_mbps"`
	Warning       string      `json:"warning"`
}
type monthDisk struct {
	Version int
	Rows    map[string]MonthRow
}
type Month struct {
	mu   sync.Mutex
	path string
	rows map[string]MonthRow
}

func NewMonth(path string) (*Month, error) {
	m := &Month{path: path, rows: map[string]MonthRow{}}
	if path == "" {
		return m, nil
	}
	var d monthDisk
	if e := read(path, &d); e != nil {
		if os.IsNotExist(e) {
			return m, nil
		}
		return nil, errors.New("TRAFFIC_MONTH_LOAD_FAILED")
	}
	if d.Version != 1 || len(d.Rows) > 64 {
		return nil, errors.New("TRAFFIC_MONTH_INVALID")
	}
	m.rows = d.Rows
	if m.rows == nil {
		m.rows = map[string]MonthRow{}
	}
	return m, nil
}
func add(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}
func (m *Month) Observe(o Observation, limit uint64, now time.Time) error {
	if len(o.Relay) == 0 || len(o.Relay) > 64 || len(o.Interface) == 0 || len(o.Interface) > 64 || len(o.Boot) != 64 || o.At.After(now.Add(30*time.Second)) || now.Sub(o.At) > 2*time.Minute || o.BootAt.After(o.At) || o.BootAt.IsZero() {
		return errors.New("TRAFFIC_OBSERVATION_INVALID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	month := o.At.UTC().Format("2006-01")
	start := time.Date(o.At.UTC().Year(), o.At.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	key := o.Relay + "|" + month
	v, exists := m.rows[key]
	rows := map[string]MonthRow{}
	nowUTC := now.UTC()
	oldest := time.Date(nowUTC.Year(), nowUTC.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0).Format("2006-01")
	for k, r := range m.rows {
		if r.Month >= oldest {
			rows[k] = r
		}
	}
	if !exists && len(rows) >= 64 {
		return errors.New("TRAFFIC_MONTH_CAPACITY")
	}
	previous := v.Last
	if !exists {
		for _, r := range rows {
			if r.Relay == o.Relay && r.Last.At.After(previous.At) {
				previous = r.Last
			}
		}
		v = MonthRow{Relay: o.Relay, Month: month, From: o.At, Partial: true, Reason: "OBSERVATION_STARTED_MID_PERIOD"}
	}
	if !previous.At.IsZero() && !o.At.After(previous.At) {
		return nil
	} // replay cannot refresh freshness or inflate usage
	delta := uint64(0)
	switch {
	case previous.At.IsZero():
		if !o.BootAt.Before(start) {
			delta = o.Counter
			v.From = o.BootAt
			v.Reason = "SINCE_BOOT; PREVIOUS_BOOTS_UNKNOWN"
		}
	case previous.Boot == o.Boot && previous.Interface == o.Interface && o.Counter >= previous.Counter:
		delta = o.Counter - previous.Counter
		if !exists {
			if o.At.Sub(previous.At) > time.Minute {
				delta = 0
				v.Reason = "UNOBSERVED_MONTH_BOUNDARY"
			} else {
				v.From = start
				v.Reason = "SAMPLED_MONTH_BOUNDARY_MAX_ONE_INTERVAL_UNCERTAINTY"
			}
		}
	case previous.Interface != o.Interface:
		v.Partial = true
		v.Reason = "INTERFACE_CHANGED; INITIAL_COUNTER_NOT_ATTRIBUTED"
	case previous.Boot != o.Boot || o.Counter < previous.Counter:
		v.Resets++
		v.Partial = true
		v.Reason = "COUNTER_RESET; GAP_BEFORE_RESET_UNKNOWN"
		if !o.BootAt.Before(start) {
			delta = o.Counter
		}
	default:
		v.Partial = true
		v.Reason = "INTERFACE_CHANGED; INITIAL_COUNTER_NOT_ATTRIBUTED"
	}
	if !previous.At.IsZero() && o.At.Sub(previous.At) > 0 && previous.Boot == o.Boot && previous.Interface == o.Interface {
		v.RateMbps = float64(delta) * 8 / o.At.Sub(previous.At).Seconds() / 1e6
	}
	v.Bytes = add(v.Bytes, delta)
	v.Last = o
	v.Limit = limit
	rows[key] = v
	if e := write(m.path, monthDisk{Version: 1, Rows: rows}); e != nil {
		return errors.New("TRAFFIC_MONTH_SAVE_FAILED")
	}
	m.rows = rows
	return nil
}
func (m *Month) Snapshot(now time.Time) []MonthRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := []MonthRow{}
	for _, v := range m.rows {
		v.Warning = ""
		v.Forecast = 0
		v.ForecastValid = false
		age := now.Sub(v.Last.At)
		if age > 2*time.Minute {
			v.Warning = "STALE_OBSERVATION"
		} else if v.Partial {
			v.Warning = "INCOMPLETE_PERIOD; NOT PROVIDER_INVOICE"
		}
		if v.Limit == 0 {
			v.Warning += "; UNKNOWN_PLAN_LIMIT"
		}
		elapsed := v.Last.At.Sub(v.From)
		if v.Month == now.UTC().Format("2006-01") && elapsed >= time.Minute && age <= 2*time.Minute {
			v.ForecastValid = true
			end := time.Date(now.UTC().Year(), now.UTC().Month()+1, 1, 0, 0, 0, 0, time.UTC)
			projected := float64(v.Bytes) * (1 + end.Sub(now).Seconds()/elapsed.Seconds())
			if projected >= float64(math.MaxUint64) {
				v.Forecast = math.MaxUint64
			} else {
				v.Forecast = uint64(projected)
			}
		}
		if !v.ForecastValid {
			v.Warning += "; FORECAST_NOT_READY"
		}
		if v.Limit > 0 && (float64(v.Bytes) >= float64(v.Limit)*.8 || v.Forecast >= v.Limit) {
			v.Warning += "; BUDGET_AT_RISK"
		}
		v.Warning = strings.Trim(v.Warning, "; ")
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Relay == rows[j].Relay {
			return rows[i].Month > rows[j].Month
		}
		return rows[i].Relay < rows[j].Relay
	})
	return rows
}
