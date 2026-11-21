package transport

import "time"

// Seconds are buckets, not per-SNI DPI policy. Factory time includes control-plane
// ticket issuance/auth; QUICHandshakeMS measures only successful quic.DialAddr.
// Never retain tickets, certificate contents, socket payloads or peer error text.
type CreationEvent struct {
	At              time.Time `json:"at"`
	Reason          string    `json:"reason"`
	Success         bool      `json:"success"`
	FactoryMS       float64   `json:"factory_ms"`
	QUICHandshakeMS float64   `json:"quic_handshake_ms"`
}
type CreationMetrics struct {
	Attempts60s, NewSessions60s, MaxAttempts60s, MaxNewSessions60s uint64
	Concurrent, MaxConcurrent                                      int
	TotalAttempts, TotalCreated                                    uint64
	Recent                                                         []CreationEvent
	Window                                                         string
}
type creationBucket struct {
	second            int64
	attempts, created uint64
}
type creationTelemetry struct {
	buckets [60]creationBucket
	metrics CreationMetrics
}

func (m *creationTelemetry) bucket(now time.Time) *creationBucket {
	sec := now.Unix()
	b := &m.buckets[sec%60]
	if b.second != sec {
		*b = creationBucket{second: sec}
	}
	return b
}
func (m *creationTelemetry) counts(now time.Time) (a, c uint64) {
	for _, b := range m.buckets {
		if b.second > now.Unix()-60 && b.second <= now.Unix() {
			a += b.attempts
			c += b.created
		}
	}
	return
}
func (m *creationTelemetry) begin(now time.Time, _ string) {
	m.bucket(now).attempts++
	m.metrics.TotalAttempts++
	m.metrics.Concurrent++
	m.metrics.MaxConcurrent = max(m.metrics.MaxConcurrent, m.metrics.Concurrent)
	a, _ := m.counts(now)
	m.metrics.MaxAttempts60s = max(m.metrics.MaxAttempts60s, a)
}
func (m *creationTelemetry) finish(now, start time.Time, reason string, c *Client, err error) {
	m.metrics.Concurrent--
	e := CreationEvent{At: now.UTC(), Reason: reason, FactoryMS: float64(now.Sub(start)) / float64(time.Millisecond), QUICHandshakeMS: -1, Success: err == nil && c != nil}
	if e.Success {
		m.bucket(now).created++
		m.metrics.TotalCreated++
		e.QUICHandshakeMS = c.handshakeMS
	}
	_, n := m.counts(now)
	m.metrics.MaxNewSessions60s = max(m.metrics.MaxNewSessions60s, n)
	m.metrics.Recent = append(m.metrics.Recent, e)
	if len(m.metrics.Recent) > 32 {
		m.metrics.Recent = append([]CreationEvent(nil), m.metrics.Recent[len(m.metrics.Recent)-32:]...)
	}
}
func (m *creationTelemetry) snapshot(now time.Time) CreationMetrics {
	v := m.metrics
	v.Attempts60s, v.NewSessions60s = m.counts(now)
	v.Recent = append([]CreationEvent(nil), v.Recent...)
	v.Window = "60 UTC second buckets; pool lifetime maxima; factory includes ticket/auth; handshake=-1 if unavailable"
	return v
}
