package clientservice

import (
	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"sort"
	"sync"
	"time"
)

var errVideoRelayCapacity = browserproxy.ErrVideoRelayAdmission
var errOpaqueGoogleCapacity = &nativePACOpenError{code: "OPAQUE_GOOGLE_RELAY_ADMISSION_CAPACITY", cause: browserproxy.ErrVideoRelayAdmission}

// Per-PC: two tracks, concurrent ranges/preload and seek replacement headroom.
// This is a bounded starting budget, not measured 36-PC VPS throughput.
const videoRelayLimit = 12
const opaqueGoogleRelayLimit = 4
const videoRelayWaitLimit = 24
const opaqueGoogleWaitLimit = 8
const videoRelayWait = 2 * time.Second
const relayUsageCapacity = 1024
const relayUsageRetention = 10 * time.Minute

type relayMinuteKey struct {
	minute          time.Time
	profile, domain string
}
type relayMinute struct {
	Opened   uint64    `json:"tunnels_opened"`
	Minute   time.Time `json:"minute_utc"`
	Profile  string    `json:"profile_id"`
	Domain   string    `json:"domain"`
	Sent     uint64    `json:"sent_bytes"`
	Received uint64    `json:"received_bytes"`
}
type relayUsageSnapshot struct {
	VideoConnections        []videoPerformance `json:"video_connections"`
	VideoOmitted            uint64             `json:"video_connections_omitted"`
	VideoScope              string             `json:"video_performance_scope"`
	OpaqueGoogleActive      int                `json:"opaque_google_active_tunnels"`
	OpaqueGoogleLimit       int                `json:"opaque_google_tunnel_limit"`
	OpaqueGoogleWaiting     int                `json:"opaque_google_waiters"`
	OpaqueGoogleFailures    uint64             `json:"opaque_google_admission_failures"`
	OpaqueGoogleCanceled    uint64             `json:"opaque_google_admission_canceled"`
	VideoCanceled           uint64             `json:"googlevideo_admission_canceled"`
	VideoIdleClosed         uint64             `json:"googlevideo_idle_closed"`
	OpaqueIdleClosed        uint64             `json:"opaque_google_idle_closed"`
	VideoWaited             uint64             `json:"googlevideo_waited"`
	VideoWaitTotalMS        int64              `json:"googlevideo_wait_total_ms"`
	VideoWaitMaxMS          int64              `json:"googlevideo_wait_max_ms"`
	CapacityDirectFallbacks uint64             `json:"ordinary_capacity_direct_fallbacks"`
	AdmissionScope          string             `json:"admission_scope"`
	TotalGoogleActive       int                `json:"google_admission_total_active"`
	SharedVideoActive       int                `json:"googlevideo_shared_limit_active"`

	Active          int                 `json:"active_tcp_tunnels"`
	Opened          uint64              `json:"tcp_tunnels_opened"`
	ActiveOrigins   []relayActiveOrigin `json:"active_origins"`
	OverflowTunnels uint64              `json:"cardinality_overflow_tunnels"`
	Scope           string              `json:"scope"`
	VideoActive     int                 `json:"googlevideo_active_tunnels"`
	VideoLimit      int                 `json:"googlevideo_tunnel_limit"`
	VideoWaiting    int                 `json:"googlevideo_waiters"`
	VideoTimeouts   uint64              `json:"googlevideo_admission_failures"`
	VideoLimitHits  uint64              `json:"googlevideo_limit_events"`
	OverflowBytes   uint64              `json:"cardinality_overflow_bytes"`
	Truncated       bool                `json:"truncated"`
	Minutes         []relayMinute       `json:"minutes"`
}
type browserRelayUsage struct {
	videos                  map[uint64]videoPerformance
	videoNext, videoLost    uint64
	activeOrigins           map[[2]string]int
	active                  int
	opened, overflowTunnels uint64
	mu                      sync.Mutex
	minutes                 map[relayMinuteKey]relayMinute
	videoAdmission          relayAdmissionPool
	opaqueAdmission         relayAdmissionPool
	capacityDirectFallbacks uint64
	overflow                uint64
}

type relayActiveOrigin struct {
	Profile string `json:"profile_id"`
	Domain  string `json:"domain"`
	Active  int    `json:"active_tunnels"`
}

func (u *browserRelayUsage) openedTunnel(profile, domain string, at time.Time) func() {
	u.mu.Lock()
	if u.minutes == nil {
		u.minutes = map[relayMinuteKey]relayMinute{}
	}
	if u.activeOrigins == nil {
		u.activeOrigins = map[[2]string]int{}
	}
	key := [2]string{profile, domain}
	_, exists := u.activeOrigins[key]
	tracked := exists || len(u.activeOrigins) < relayUsageCapacity
	u.active++
	u.opened++
	if tracked {
		u.activeOrigins[key]++
	} else {
		u.overflowTunnels++
	}
	for k := range u.minutes {
		if at.Sub(k.minute) > relayUsageRetention {
			delete(u.minutes, k)
		}
	}
	mk := relayMinuteKey{at.UTC().Truncate(time.Minute), profile, domain}
	m, ok := u.minutes[mk]
	if ok || len(u.minutes) < relayUsageCapacity {
		m.Minute = mk.minute
		m.Profile = profile
		m.Domain = domain
		m.Opened++
		u.minutes[mk] = m
	} else {
		u.overflowTunnels++
	}
	u.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			u.active--
			if tracked {
				u.activeOrigins[key]--
				if u.activeOrigins[key] == 0 {
					delete(u.activeOrigins, key)
				}
			}
		})
	}
}

func (c *Controller) relayUsage() *browserRelayUsage {
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	if c.browser.usage == nil {
		c.browser.usage = &browserRelayUsage{minutes: map[relayMinuteKey]relayMinute{}}
	}
	return c.browser.usage
}
func (u *browserRelayUsage) account(profile, domain string, tx, rx uint64, at time.Time) {
	u.accountIO(profile, domain, tx, rx, at, 0)
}
func (u *browserRelayUsage) accountIO(profile, domain string, tx, rx uint64, at time.Time, videoID uint64) {
	if tx+rx == 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.videoIO(videoID, tx, rx, at)
	for k := range u.minutes {
		if at.Sub(k.minute) > relayUsageRetention {
			delete(u.minutes, k)
		}
	}
	if u.minutes == nil {
		u.minutes = map[relayMinuteKey]relayMinute{}
	}
	key := relayMinuteKey{at.UTC().Truncate(time.Minute), profile, domain}
	v, ok := u.minutes[key]
	if !ok && len(u.minutes) >= relayUsageCapacity {
		u.overflow += tx + rx
		return
	}
	v.Minute, v.Profile, v.Domain = key.minute, profile, domain
	v.Sent += tx
	v.Received += rx
	u.minutes[key] = v
}
func (u *browserRelayUsage) snapshot() relayUsageSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	v, o := u.videoAdmission, u.opaqueAdmission
	s := relayUsageSnapshot{VideoActive: v.active, OpaqueGoogleActive: o.active, SharedVideoActive: v.active, TotalGoogleActive: v.active + o.active, VideoLimit: videoRelayLimit, OpaqueGoogleLimit: opaqueGoogleRelayLimit, VideoLimitHits: v.hits, VideoWaiting: v.waiting, OpaqueGoogleWaiting: o.waiting, VideoTimeouts: v.failures, OpaqueGoogleFailures: o.failures, VideoCanceled: v.canceled, OpaqueGoogleCanceled: o.canceled, VideoIdleClosed: v.idleClosed, OpaqueIdleClosed: o.idleClosed, VideoWaited: v.waited, VideoWaitTotalMS: v.waitTotal.Milliseconds(), VideoWaitMaxMS: v.waitMax.Milliseconds(), CapacityDirectFallbacks: u.capacityDirectFallbacks, AdmissionScope: "DEDICATED_GOOGLEVIDEO_12_PLUS_OTHER_GOOGLE_4; shared_limit_active is legacy video-only", OverflowBytes: u.overflow, Minutes: []relayMinute{}}
	s.VideoConnections = u.videoSnapshot(time.Now())
	s.VideoOmitted = u.videoLost + uint64(len(u.videos)-len(s.VideoConnections))
	s.VideoScope = "upstream wire bytes (TLS included); start=admission before relay OPEN; average includes idle, receive span includes inter-read gaps; NOT segment/FPS/page proof"
	s.Active = u.active
	s.Opened = u.opened
	s.OverflowTunnels = u.overflowTunnels
	s.Scope = "browser TCP application payload; native + PAC; excludes QUIC overhead/origin probes"
	s.ActiveOrigins = []relayActiveOrigin{}
	for key, active := range u.activeOrigins {
		s.ActiveOrigins = append(s.ActiveOrigins, relayActiveOrigin{key[0], key[1], active})
	}
	sort.Slice(s.ActiveOrigins, func(i, j int) bool {
		a, b := s.ActiveOrigins[i], s.ActiveOrigins[j]
		if a.Active != b.Active {
			return a.Active > b.Active
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return a.Domain < b.Domain
	})
	if len(s.ActiveOrigins) > 64 {
		s.ActiveOrigins = s.ActiveOrigins[:64]
		s.Truncated = true
	}
	for _, v := range u.minutes {
		if time.Since(v.Minute) <= relayUsageRetention {
			s.Minutes = append(s.Minutes, v)
		}
	}
	sort.Slice(s.Minutes, func(i, j int) bool {
		a, b := s.Minutes[i], s.Minutes[j]
		if !a.Minute.Equal(b.Minute) {
			return a.Minute.After(b.Minute)
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return a.Domain < b.Domain
	})
	if len(s.Minutes) > 64 {
		s.Minutes = s.Minutes[:64]
		s.Truncated = true
	}
	s.Truncated = s.Truncated || s.VideoOmitted > 0 || u.overflow > 0 || u.overflowTunnels > 0
	return s
}

func isVideo(q browserproxy.Request) bool { return flowpolicy.DomainMatches(q.Host, "googlevideo.com") }

// Do not impose web admission/idle budgets on mtalk/push and other TCP ports.
func otherGoogleWebAdmission(q browserproxy.Request, p browserproxy.Plan) bool {
	return q.Port == 443 && !isVideo(q) && !restrictiveBrowserDomain(q.Host) && (browserGoogleDestination(p.Destination) || ordinaryGoogleDomain(q.Host))
}

// Called while browser.mu is already held by status IPC.
func (c *Controller) relayUsageLocked() relayUsageSnapshot {
	if c.browser.usage == nil {
		return (&browserRelayUsage{}).snapshot()
	}
	return c.browser.usage.snapshot()
}
