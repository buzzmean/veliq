package traffic

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientSessionUTCDateRestoreFreezeIsolationAndOverflow(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "usage.json")
	c := NewClient()
	c.Configure(path, "DO_NOT_LOG_DEVICE_ID")
	k := Key{Profile: "chrome", Service: "youtube-media", Subgroup: "googlevideo:sn-a", Reason: "LOCAL_HEALTH_NOT_CONFIRMED", Relay: "VPS-01"}
	for i := 0; i < ClientKeys+10; i++ {
		q := k
		q.Profile = fmt.Sprint(i)
		c.Add(q, 1, 2, now)
	}
	s := c.Snapshot(now)
	if s.DayTotal.Sent != ClientKeys+10 || s.SessionTotal.Received != 2*(ClientKeys+10) || s.DayOverflow.Sent != 10 || s.SessionOmitted == 0 {
		t.Fatal(s)
	}
	if e := c.Flush(); e != nil {
		t.Fatal(e)
	}
	restored := NewClient()
	restored.Configure(path, "DO_NOT_LOG_DEVICE_ID")
	s = restored.Snapshot(now)
	if s.DayTotal.Sent != ClientKeys+10 || s.SessionTotal.Sent != 0 {
		t.Fatal("restart reset/double counted day", s)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "DO_NOT_LOG_DEVICE_ID") {
		t.Fatal("private device epoch exposed")
	}
	other := NewClient()
	other.Configure(path, "another-device")
	if other.Snapshot(now).DayTotal.Sent != 0 {
		t.Fatal("shared image stole another PC counters")
	}
	tomorrow := now.AddDate(0, 0, 1)
	c.Add(k, 5, 6, tomorrow)
	if c.Snapshot(tomorrow).DayTotal.Sent != 5 {
		t.Fatal("overflow assigned to next UTC day")
	}
}
func TestClientConcurrentAddAndFlushNeverLosesBytes(t *testing.T) {
	c := NewClient()
	c.Configure(filepath.Join(t.TempDir(), "usage.json"), "epoch")
	now := time.Now()
	k := Key{Relay: "relay", Profile: "app"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 500; n++ {
				c.Add(k, 1, 2, now)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 5; n++ {
			if e := c.Flush(); e != nil {
				t.Error(e)
			}
		}
	}()
	wg.Wait()
	if v := c.Snapshot(now); v.SessionTotal.Sent != 4000 || v.DayTotal.Received != 8000 {
		t.Fatal(v)
	}
}
func TestMonthNICPersistenceCounterResetsReplayAndPartialPeriod(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "month.json")
	m, e := NewMonth(path)
	if e != nil {
		t.Fatal(e)
	}
	o := Observation{Relay: "VPS-PRIMARY", Interface: "eth0", Boot: strings.Repeat("a", 64), BootAt: now.Add(-time.Hour), At: now, Counter: 100}
	if e = m.Observe(o, 120, now); e != nil {
		t.Fatal(e)
	}
	o.At = now.Add(5 * time.Second)
	o.Counter = 110
	if e = m.Observe(o, 120, o.At); e != nil {
		t.Fatal(e)
	}
	if s := m.Snapshot(o.At); len(s) != 1 || s[0].Bytes != 110 || !s[0].Partial || !strings.Contains(s[0].Warning, "BUDGET_AT_RISK") {
		t.Fatal(s)
	}
	replay := o
	replay.Counter = 999
	if e = m.Observe(replay, 120, o.At); e != nil {
		t.Fatal(e)
	}
	if m.Snapshot(o.At)[0].Bytes != 110 {
		t.Fatal("replay inflated quota")
	}
	m, e = NewMonth(path)
	if e != nil {
		t.Fatal(e)
	}
	o.At = o.At.Add(5 * time.Second)
	o.Counter = 10
	if e = m.Observe(o, 120, o.At); e != nil {
		t.Fatal(e)
	}
	if s := m.Snapshot(o.At)[0]; s.Bytes != 120 || s.Resets != 1 || !s.Partial {
		t.Fatal(s)
	}
	o.At = time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	o.Counter = 200
	if e = m.Observe(o, 120, o.At); e != nil {
		t.Fatal(e)
	}
	s := m.Snapshot(o.At)
	if len(s) != 2 || s[0].Month != "2026-11" || s[0].Bytes != 0 || !strings.Contains(s[0].Warning, "INCOMPLETE_PERIOD") {
		t.Fatal("unobserved month boundary fabricated zero usage", s)
	}
}
func TestMonthFailureCannotPublishPartialInMemoryCounter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "parent", "usage.json")
	m, _ := NewMonth(path)
	if e := os.WriteFile(filepath.Dir(path), []byte("file"), 0600); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	o := Observation{Relay: "relay", Interface: "eth0", Boot: strings.Repeat("a", 64), BootAt: now.Add(-time.Hour), At: now, Counter: 100}
	if m.Observe(o, 1000, now) == nil || len(m.Snapshot(now)) != 0 {
		t.Fatal("failed write committed memory")
	}
}
