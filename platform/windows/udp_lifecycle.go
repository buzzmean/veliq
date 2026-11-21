package windowsplatform

import "time"

// Lifetime state is bounded independently of concurrent opens. Non-media flows
// cannot consume the adaptive reserve; active flows are never evicted for admission.
const (
	udpCaptureLimit = 512
	udpMediaReserve = 128
	udpDNSIdle      = 5 * time.Second
	udpFlowIdle     = 30 * time.Second
)

type udpAdmission struct{ total, ordinary int }

// Caller serializes with the capture map lock, including release.
func (a *udpAdmission) acquire(media bool) bool {
	if a.total >= udpCaptureLimit || (!media && a.ordinary >= udpCaptureLimit-udpMediaReserve) {
		return false
	}
	a.total++
	if !media {
		a.ordinary++
	}
	return true
}
func (a *udpAdmission) release(media bool) {
	a.total--
	if !media {
		a.ordinary--
	}
}
func udpIdleLimit(t Tuple, media bool) time.Duration {
	if t.Destination.Port() == 53 && !media {
		return udpDNSIdle
	}
	return udpFlowIdle
}

// Queueing and successful receive both refresh last activity under the same map
// lock. Equality is idle; queued work always wins. No server timeout guesswork.
func udpIdle(now, last time.Time, pending int, limit time.Duration) bool {
	return pending == 0 && !last.IsZero() && now.Sub(last) >= limit
}
