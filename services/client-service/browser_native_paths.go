package clientservice

import "time"

// Per-activation ingress proof. An authenticated PAC authority delegated into
// WinDivert is deliberately NOT evidence of a native-only browser ingress.
type nativeIngressCounters struct {
	Accepted  uint64 `json:"accepted"`
	Opened    uint64 `json:"opened"`
	Failed    uint64 `json:"failed"`
	Exchanges uint64 `json:"bidirectional_exchanges"`
	Active    uint64 `json:"active"`
	Sent      uint64 `json:"sent_bytes"`
	Received  uint64 `json:"received_bytes"`
}
type nativeIngressMetrics struct {
	nativeIngressCounters
	FirstOpened     time.Time `json:"first_opened_at,omitzero"`
	FirstExchange   time.Time `json:"first_exchange_at,omitzero"`
	FirstOpenMS     int64     `json:"enable_to_first_open_ms"`
	FirstExchangeMS int64     `json:"enable_to_first_exchange_ms"`
}

func newIngressMetrics() nativeIngressMetrics {
	return nativeIngressMetrics{FirstOpenMS: -1, FirstExchangeMS: -1}
}
func (p *nativeBrowserProfileStatus) ingress(ingress string) *nativeIngressMetrics {
	switch ingress {
	case "NATIVE_TCP":
		return &p.NativeOnly
	case "PAC_NATIVE_UPSTREAM":
		return &p.PACUpstream
	}
	return nil
}
func addIngress(a *nativeIngressCounters, b nativeIngressCounters) {
	a.Accepted += b.Accepted
	a.Opened += b.Opened
	a.Failed += b.Failed
	a.Exchanges += b.Exchanges
	a.Active += b.Active
	a.Sent += b.Sent
	a.Received += b.Received
}
