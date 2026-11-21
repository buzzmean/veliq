package traffic

import (
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

// Two UTC days of worst-case bounded keys still fit the 1MiB state envelope.
const ClientKeys = 512

type Key struct {
	Profile  string `json:"profile"`
	Service  string `json:"service"`
	Subgroup string `json:"subgroup"`
	Reason   string `json:"reason"`
	Relay    string `json:"logical_relay"`
}
type Bytes struct{ Sent, Received uint64 }
type ClientRow struct {
	Key
	Bytes
	Day string `json:"day_utc,omitempty"`
}
type clientDisk struct {
	Version  int
	Epoch    string
	Days     []ClientRow
	Overflow map[string]Bytes
}
type ClientSnapshot struct {
	Session                      []ClientRow `json:"session"`
	Days                         []ClientRow `json:"days"`
	SessionTotal, DayTotal       Bytes
	SessionOverflow, DayOverflow Bytes
	SessionOmitted, DaysOmitted  int
	State                        string `json:"state"`
	Error                        string `json:"error,omitempty"`
	Scope                        string `json:"scope"`
}
type Client struct {
	mu                            sync.Mutex
	session                       map[Key]Bytes
	days                          map[string]map[Key]Bytes
	sessionOverflow               Bytes
	dayOverflow                   map[string]Bytes
	saveMu                        sync.Mutex
	path, epoch, state, lastError string
}

func NewClient() *Client {
	return &Client{session: map[Key]Bytes{}, days: map[string]map[Key]Bytes{}, dayOverflow: map[string]Bytes{}, state: "MEMORY_ONLY"}
}
func (c *Client) Configure(path, epoch string) {
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == path && c.epoch == epoch {
		return
	}
	c.path = path
	c.epoch = epoch
	c.days = map[string]map[Key]Bytes{}
	c.dayOverflow = map[string]Bytes{}
	c.lastError = ""
	if path == "" || epoch == "" {
		c.state = "MEMORY_ONLY"
		return
	}
	var disk clientDisk
	if e := read(path, &disk); e != nil {
		if !os.IsNotExist(e) {
			c.lastError = "TRAFFIC_STATE_LOAD_FAILED"
		}
		c.state = "NEW_OBSERVATION"
		return
	}
	if disk.Version != 1 || disk.Epoch != epoch || len(disk.Days) > 2*ClientKeys {
		c.state = "DEVICE_CHANGED_OR_IMAGE_COUNTERS_IGNORED"
		return
	}
	uniqueDays := map[string]int{}
	for _, row := range disk.Days {
		uniqueDays[row.Day]++
		if len(uniqueDays) > 2 || uniqueDays[row.Day] > ClientKeys || len(disk.Overflow) > 2 {
			c.lastError = "TRAFFIC_STATE_CARDINALITY_INVALID"
			return
		}
		if bounded(row.Key) != row.Key {
			c.lastError = "TRAFFIC_STATE_INVALID_KEY"
			return
		}
		if _, e := time.Parse("2006-01-02", row.Day); e != nil {
			c.lastError = "TRAFFIC_STATE_INVALID_DAY"
			return
		}
	}
	for _, row := range disk.Days {
		if c.days[row.Day] == nil {
			c.days[row.Day] = map[Key]Bytes{}
		}
		c.days[row.Day][row.Key] = row.Bytes
	}
	if disk.Overflow != nil {
		c.dayOverflow = disk.Overflow
	}
	c.state = "RESTORED_FOR_SAME_DEVICE_ID"
}
func bounded(k Key) Key {
	// Local diagnostic keys only, never payload, URL, device identity or token.
	if len(k.Profile) > 128 {
		k.Profile = "other"
	}
	if len(k.Service) > 32 {
		k.Service = "other"
	}
	if len(k.Subgroup) > 128 {
		k.Subgroup = "other"
	}
	if len(k.Reason) > 96 {
		k.Reason = "other"
	}
	if len(k.Relay) > 64 {
		k.Relay = "other"
	}
	return k
}
func plus(v Bytes, tx, rx uint64) Bytes {
	v.Sent = add(v.Sent, tx)
	v.Received = add(v.Received, rx)
	return v
}
func (c *Client) Add(k Key, tx, rx uint64, now time.Time) {
	if tx == 0 && rx == 0 || k.Relay == "" {
		return
	}
	k = bounded(k)
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.session[k]
	if ok || len(c.session) < ClientKeys {
		c.session[k] = plus(v, tx, rx)
	} else {
		c.sessionOverflow = plus(c.sessionOverflow, tx, rx)
	}
	day := now.UTC().Format("2006-01-02")
	for old := range c.days {
		if old < now.UTC().AddDate(0, 0, -1).Format("2006-01-02") {
			delete(c.days, old)
			delete(c.dayOverflow, old)
		}
	}
	if c.days[day] == nil {
		c.days[day] = map[Key]Bytes{}
	}
	v, ok = c.days[day][k]
	if ok || len(c.days[day]) < ClientKeys {
		c.days[day][k] = plus(v, tx, rx)
	} else {
		c.dayOverflow[day] = plus(c.dayOverflow[day], tx, rx)
	}
}
func (c *Client) Flush() error {
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	if c.path == "" || c.epoch == "" {
		c.mu.Unlock()
		return nil
	}
	d := clientDisk{Version: 1, Epoch: c.epoch, Overflow: map[string]Bytes{}}
	path := c.path
	for day, v := range c.dayOverflow {
		d.Overflow[day] = v
	}
	for day, rows := range c.days {
		for k, v := range rows {
			d.Days = append(d.Days, ClientRow{k, v, day})
		}
	}
	c.mu.Unlock()
	err := write(path, d)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.lastError = "TRAFFIC_STATE_SAVE_FAILED"
		return errors.New(c.lastError)
	}
	c.lastError = ""
	return nil
}
func (c *Client) Snapshot(now time.Time) ClientSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := ClientSnapshot{State: c.state, Error: c.lastError, SessionOverflow: c.sessionOverflow, DayOverflow: c.dayOverflow[now.UTC().Format("2006-01-02")], Scope: "successful relay application payload (TLS included), logical policy relay ID; excludes QUIC/IP overhead; UTC day; freeze/device replacement can reset local tally; server NIC meter is separate"}
	for k, v := range c.session {
		s.Session = append(s.Session, ClientRow{Key: k, Bytes: v})
		s.SessionTotal = plus(s.SessionTotal, v.Sent, v.Received)
	}
	day := now.UTC().Format("2006-01-02")
	for d, rows := range c.days {
		for k, v := range rows {
			s.Days = append(s.Days, ClientRow{k, v, d})
			if d == day {
				s.DayTotal = plus(s.DayTotal, v.Sent, v.Received)
			}
		}
	}
	s.SessionTotal = plus(s.SessionTotal, s.SessionOverflow.Sent, s.SessionOverflow.Received)
	s.DayTotal = plus(s.DayTotal, s.DayOverflow.Sent, s.DayOverflow.Received)
	order := func(rows []ClientRow) {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Sent+rows[i].Received > rows[j].Sent+rows[j].Received })
	}
	order(s.Session)
	order(s.Days)
	if len(s.Session) > 48 {
		s.SessionOmitted = len(s.Session) - 48
		s.Session = s.Session[:48]
	}
	if len(s.Days) > 48 {
		s.DaysOmitted = len(s.Days) - 48
		s.Days = s.Days[:48]
	}
	return s
}
