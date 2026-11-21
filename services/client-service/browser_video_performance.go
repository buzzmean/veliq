package clientservice

import (
	"sort"
	"time"
)

const videoPerformanceCapacity = 128

// Wire-level upstream metrics only. TLS ServerHello counts as a first byte;
// encrypted HTTP requests, media segments and decoder FPS are not observable.
type videoPerformance struct {
	ID              uint64    `json:"id"`
	Port            uint16    `json:"port,omitempty"`
	Network         string    `json:"network,omitempty"`
	Profile         string    `json:"profile_id"`
	Domain          string    `json:"domain"`
	Destination     string    `json:"destination"`
	Ingress         string    `json:"ingress"`
	Started         time.Time `json:"started"`
	Opened          time.Time `json:"opened_at,omitzero"`
	FirstWrite      time.Time `json:"first_write_at,omitzero"`
	FirstRead       time.Time `json:"first_byte_at,omitzero"`
	LastRead        time.Time `json:"last_read_at,omitzero"`
	Closed          time.Time `json:"closed_at,omitzero"`
	AdmissionMS     float64   `json:"admission_ms"`
	OpenMS          float64   `json:"relay_open_ms"`
	FirstByteMS     float64   `json:"first_byte_ms"`
	WriteToFirstMS  float64   `json:"write_to_first_byte_ms"`
	AverageMbps     float64   `json:"average_receive_mbps"`
	ReceiveSpanMbps float64   `json:"receive_span_mbps"`
	MaxReadGapMS    float64   `json:"max_read_gap_ms"`
	Sent            uint64    `json:"sent_bytes"`
	Received        uint64    `json:"received_bytes"`
	State           string    `json:"state"`
	Failure         string    `json:"failure_reason,omitempty"`
	firstReadBytes  uint64
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
func (u *browserRelayUsage) beginVideo(v videoPerformance) uint64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.videos == nil {
		u.videos = make(map[uint64]videoPerformance)
	}
	if len(u.videos) == videoPerformanceCapacity {
		var oldest uint64
		for id, r := range u.videos {
			if !r.Closed.IsZero() && (oldest == 0 || id < oldest) {
				oldest = id
			}
		}
		if oldest == 0 {
			u.videoLost++
			return 0
		}
		delete(u.videos, oldest)
		u.videoLost++
	}
	u.videoNext++
	v.ID = u.videoNext
	v.State = "ADMISSION"
	v.AdmissionMS = -1
	v.OpenMS = -1
	v.FirstByteMS = -1
	v.WriteToFirstMS = -1
	v.AverageMbps = -1
	v.ReceiveSpanMbps = -1
	u.videos[v.ID] = v
	return v.ID
}
func (u *browserRelayUsage) videoOpened(id uint64, admitted, opened time.Time, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	v, ok := u.videos[id]
	if !ok {
		return
	}
	v.AdmissionMS = milliseconds(admitted.Sub(v.Started))
	v.OpenMS = milliseconds(opened.Sub(admitted))
	if err != nil {
		v.State = "OPEN_FAILED"
		v.Failure = nativeFailureCode(err)
		v.Closed = opened
	} else {
		v.Opened = opened
		v.State = "OPENED_NO_REPLY"
	}
	u.videos[id] = v
}
func (u *browserRelayUsage) videoIO(id, tx, rx uint64, now time.Time) {
	// Caller holds u.mu (same critical section as byte accounting).
	v, ok := u.videos[id]
	if !ok {
		return
	}
	v.Sent += tx
	v.Received += rx
	if tx > 0 && v.FirstWrite.IsZero() {
		v.FirstWrite = now
	}
	if rx > 0 {
		if v.FirstRead.IsZero() {
			v.FirstRead = now
			v.firstReadBytes = rx
			v.FirstByteMS = milliseconds(now.Sub(v.Started))
			if !v.FirstWrite.IsZero() {
				v.WriteToFirstMS = milliseconds(now.Sub(v.FirstWrite))
			}
		}
		if !v.LastRead.IsZero() {
			gap := milliseconds(now.Sub(v.LastRead))
			if gap > v.MaxReadGapMS {
				v.MaxReadGapMS = gap
			}
		}
		v.LastRead = now
		if v.Closed.IsZero() {
			v.State = "RECEIVING"
		}
	}
	u.videos[id] = v
}
func (u *browserRelayUsage) videoClosed(id uint64, idle bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	v, ok := u.videos[id]
	if !ok {
		return
	}
	v.Closed = time.Now()
	v.State = "CLOSED"
	if idle {
		v.State = "IDLE_CLOSED"
	}
	u.videos[id] = v
}
func (u *browserRelayUsage) videoSnapshot(now time.Time) []videoPerformance {
	// Caller holds u.mu. Include live connections; never fabricate no-reply rates.
	rows := make([]videoPerformance, 0, len(u.videos))
	for _, v := range u.videos {
		end := now
		if !v.Closed.IsZero() {
			end = v.Closed
		}
		if v.Received > 0 && end.After(v.Started) {
			v.AverageMbps = float64(v.Received) * 8 / end.Sub(v.Started).Seconds() / 1e6
		}
		if !v.FirstRead.IsZero() && v.LastRead.Sub(v.FirstRead) >= time.Millisecond {
			v.ReceiveSpanMbps = float64(v.Received-v.firstReadBytes) * 8 / v.LastRead.Sub(v.FirstRead).Seconds() / 1e6
		}
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Closed.IsZero() != rows[j].Closed.IsZero() {
			return rows[i].Closed.IsZero()
		}
		return rows[i].ID > rows[j].ID
	})
	if len(rows) > 24 {
		rows = rows[:24]
	}
	return rows
}
