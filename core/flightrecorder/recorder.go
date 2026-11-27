package flightrecorder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
)

type snapshotRequest struct {
	limit int
	reply chan []Entry
}
type Recorder struct {
	admission        sync.RWMutex
	stopping         chan struct{}
	header           Header
	start            time.Time
	input            chan Frame
	requests         chan snapshotRequest
	status           atomic.Pointer[Status]
	dropped          atomic.Uint64
	closed           atomic.Bool
	ring             [RingCapacity]Entry
	ringHead         int
	ringCount        int
	slot             int
	segment          []byte
	dirty            bool
	sequence         uint64
	lastResource     Frame
	budgetStart      uint64
	budgetUsed       int
	lastHeartbeat    uint64
	lastIncident     uint64
	postUntil        uint64
	postRemaining    int
	incident         string
	incidentAt       time.Time
	lastPublished    time.Time
	lastWriteAttempt time.Time
	finalFlushed     bool
	stats            Status
	promote          func(Promotion) bool
}

func New(h Header, promote func(Promotion) bool) *Recorder {
	h.Schema = 1
	r := &Recorder{stopping: make(chan struct{}), header: h, start: time.Now(), input: make(chan Frame, QueueCapacity), requests: make(chan snapshotRequest, 2), promote: promote}
	r.stats = Status{Schema: 1, Coverage: "NOT_STARTED", Cause: "UNKNOWN"}
	r.publish()
	return r
}
func (r *Recorder) offer(f Frame) bool {
	if r == nil {
		return false
	}
	if !r.admission.TryRLock() {
		r.dropped.Add(1)
		return false
	}
	defer r.admission.RUnlock()
	if r.closed.Load() {
		r.dropped.Add(1)
		return false
	}
	now := time.Now()
	f.ObservedAt = now.UTC()
	f.ElapsedNS = uint64(max(0, now.Sub(r.start)))
	select {
	case r.input <- f:
		return true
	default:
		r.dropped.Add(1)
		return false
	}
}

// The caller supplies already allowlisted diagnostic facts. Only the worker
// validates/serializes/writes them. The producer never waits for disk or mutexes.
func (r *Recorder) OfferFact(e clubhealth.Diagnostic) bool {
	if r == nil || e.Observer == "FLIGHT_RECORDER" {
		return false
	}
	return r.offer(Frame{Fact: e})
}
func (r *Recorder) OfferResource(s ResourceSample, g RuntimeSample, state RuntimeState) bool {
	return r.offer(Frame{Resource: s, Runtime: g, State: state})
}
func (r *Recorder) Status() Status {
	if r == nil {
		return Status{Schema: 1, Coverage: "NOT_CONFIGURED", Cause: "UNKNOWN"}
	}
	s := *r.status.Load()
	s.Dropped = r.dropped.Load()
	return s
}
func (r *Recorder) Snapshot(ctx context.Context, limit int) ([]Entry, error) {
	if limit < 1 || limit > RingCapacity {
		return nil, errors.New("FLIGHT_CONTEXT_LIMIT")
	}
	if r == nil || r.closed.Load() {
		return nil, errors.New("FLIGHT_NOT_RUNNING")
	}
	reply := make(chan []Entry, 1)
	select {
	case r.requests <- snapshotRequest{limit, reply}:
	case <-r.stopping:
		return nil, errors.New("FLIGHT_STOPPING")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case out := <-reply:
		return out, nil
	case <-r.stopping:
		return nil, errors.New("FLIGHT_STOPPING")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (r *Recorder) publish() {
	r.stats.WindowFrames = r.ringCount
	if r.dirty {
		r.stats.PendingBytes = len(r.segment)
	} else {
		r.stats.PendingBytes = 0
	}
	if r.ringCount > 0 {
		r.stats.OldestObservedAt = r.ring[r.ringHead].Frame.ObservedAt
	}
	s := r.stats
	s.Dropped = r.dropped.Load()
	r.status.Store(&s)
	r.lastPublished = time.Now()
}
func (r *Recorder) Run(ctx context.Context, store Storage) {
	defer r.closed.Store(true)
	if !validHeader(r.header) {
		r.admission.Lock()
		r.closed.Store(true)
		close(r.stopping)
		r.admission.Unlock()
		r.stats.Coverage = "INVALID_HEADER"
		r.stats.Invalid++
		r.dropped.Add(uint64(len(r.input)))
		r.publish()
		return
	}
	r.load(store, time.Now())
	r.append(Frame{Marker: "RECORDER_STARTED", ObservedAt: time.Now().UTC()}, store)
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case f := <-r.input:
			r.append(f, store)
		case q := <-r.requests:
			r.publish()
			q.reply <- r.recent(q.limit)
		case <-tick.C:
			r.flush(store)
			r.publish()
		case <-ctx.Done():
			r.admission.Lock()
			r.closed.Store(true)
			close(r.stopping)
			r.admission.Unlock()
			for n := 0; n < QueueCapacity; n++ {
				select {
				case f := <-r.input:
					r.append(f, store)
				default:
					n = QueueCapacity
				}
			}
			r.append(Frame{Marker: "RECORDER_STOPPED", ObservedAt: time.Now().UTC(), ElapsedNS: uint64(max(0, time.Since(r.start)))}, store)
			r.flushAt(store, time.Now(), true)
			r.stats.Closed = true
			r.publish()
			return
		}
	}
}
func validHeader(h Header) bool {
	return h.Schema == 1 && (clubhealth.Reporter{PC: h.PC, Version: h.Version, Source: h.Source, Session: h.Session, ServicePID: h.ServicePID}).Valid()
}
func validFrame(f Frame, now time.Time) bool {
	if f.State.Known & ^(StateCapture|StateAutomatic|StateActivation|StateIPC) != 0 {
		return false
	}
	switch f.State.ActivationState {
	case "", "UNAVAILABLE", "CODE_REQUIRED", "ACTIVATED", "ACTIVATING", "ACTIVATION_ERROR", "CLUB_IMAGE_STAGED", "CODE_STAGED":
	default:
		return false
	}
	if !f.State.CaptureTrafficKnown && (f.State.CaptureRXBytes != 0 || f.State.CaptureTXBytes != 0) {
		return false
	}
	if f.State.Known&StateActivation == 0 && f.State.ActivationState != "" {
		return false
	}
	if f.ObservedAt.Before(now.Add(-Retention)) || f.ObservedAt.After(now.Add(time.Minute)) {
		return false
	}
	if f.Marker != "" {
		if f.Fact != (clubhealth.Diagnostic{}) || f.Resource != (ResourceSample{}) || f.Runtime != (RuntimeSample{}) || f.State != (RuntimeState{}) {
			return false
		}
		return f.Marker == "RECORDER_STARTED" || f.Marker == "RECORDER_STOPPED"
	}
	if f.Fact.ID != "" {
		if f.Resource != (ResourceSample{}) || f.Runtime != (RuntimeSample{}) || f.State != (RuntimeState{}) {
			return false
		}
		return f.Fact.Valid(now)
	}
	s := f.Resource
	return s.PID != 0 && s.Source != "" && len(s.Source) <= 32 && len(s.ErrorCode) <= 64 && s.Known&^(ResourceCPU|ResourceWorkingSet|ResourcePrivate|ResourceIO|ResourceHandles|ResourceThreads|ResourceSystemCPU) == 0 &&
		(s.Source == "WINDOWS_NATIVE" || s.Source == "LINUX_NATIVE" || s.Source == "LINUX_RUSAGE" || s.Source == "LINUX_PROC_RUSAGE" || s.Source == "UNAVAILABLE" || s.Source == "UNSUPPORTED" || s.Source == "FIXTURE")
}
func (r *Recorder) load(store Storage, now time.Time) {
	if !validHeader(r.header) {
		r.stats.Coverage = "INVALID_HEADER"
		r.publish()
		return
	}
	var inherited ContextGaps
	var loaded []Entry
	var latest time.Time
	latestSlot := -1
	for slot := 0; slot < SegmentCount; slot++ {
		if store.Read == nil {
			break
		}
		raw, err := store.Read(slot)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				r.stats.CorruptSegments++
			}
			continue
		}
		if len(raw) > SegmentBytes {
			r.stats.CorruptSegments++
			continue
		}
		scan := bufio.NewScanner(bytes.NewReader(raw))
		scan.Buffer(make([]byte, MaxLineBytes), MaxLineBytes)
		var h Header
		if !scan.Scan() || json.Unmarshal(scan.Bytes(), &h) != nil || !validHeader(h) {
			r.stats.CorruptSegments++
			continue
		}

		inherited.Dropped = max(inherited.Dropped, h.Gaps.Dropped)
		inherited.UnpersistedSegments = max(inherited.UnpersistedSegments, h.Gaps.UnpersistedSegments)
		inherited.WriteFailures = max(inherited.WriteFailures, h.Gaps.WriteFailures)
		inherited.WriteThrottled = max(inherited.WriteThrottled, h.Gaps.WriteThrottled)
		good := true
		for scan.Scan() {
			var f Frame
			if json.Unmarshal(scan.Bytes(), &f) != nil {
				good = false
				break
			}
			if f.ObservedAt.Before(now.Add(-Retention)) {
				r.stats.WindowEvictions++
				continue
			}
			if !validFrame(f, now) {
				good = false
				break
			}
			loaded = append(loaded, Entry{h, f})
			if f.ObservedAt.After(latest) {
				latest = f.ObservedAt
				latestSlot = slot
				r.stats.PreviousTailUncertain = f.Marker != "RECORDER_STOPPED"
			}
		}
		if !good || scan.Err() != nil {
			r.stats.CorruptSegments++
		}
	}
	sort.SliceStable(loaded, func(i, j int) bool { return loaded[i].Frame.ObservedAt.Before(loaded[j].Frame.ObservedAt) })
	if len(loaded) > RingCapacity {
		r.stats.WindowEvictions += uint64(len(loaded) - RingCapacity)
		loaded = loaded[len(loaded)-RingCapacity:]
	}
	for _, entry := range loaded {
		r.addRing(entry)
	}
	if latestSlot >= 0 {
		r.slot = (latestSlot + 1) % SegmentCount
	}
	r.dropped.Add(inherited.Dropped)
	r.stats.UnpersistedSegments = inherited.UnpersistedSegments
	r.stats.WriteFailures = inherited.WriteFailures
	r.stats.WriteThrottled = inherited.WriteThrottled
	r.stats.Coverage = "MEMORY_PENDING_DURABILITY"
	if inherited.UnpersistedSegments > 0 || inherited.Dropped > 0 || r.stats.CorruptSegments > 0 {
		r.stats.Coverage = "PARTIAL_LOCAL_WINDOW"
	}
	r.publish()
}
func (r *Recorder) addRing(e Entry) {
	if r.ringCount == RingCapacity {
		r.ring[r.ringHead] = e
		r.ringHead = (r.ringHead + 1) % RingCapacity
		r.stats.WindowEvictions++
		return
	}
	r.ring[(r.ringHead+r.ringCount)%RingCapacity] = e
	r.ringCount++
}
func (r *Recorder) recent(limit int) []Entry {
	n := min(limit, r.ringCount)
	out := make([]Entry, n)
	for i := 0; i < n; i++ {
		out[i] = r.ring[(r.ringHead+r.ringCount-n+i)%RingCapacity]
	}
	return out
}
func (r *Recorder) append(f Frame, store Storage) {
	if !validFrame(f, time.Now()) {
		r.stats.Invalid++
		return
	}
	r.sequence++
	f.Sequence = r.sequence
	if f.Resource.PID != 0 {
		previous := r.lastResource
		span := uint64(0)
		if f.ElapsedNS > previous.ElapsedNS {
			span = f.ElapsedNS - previous.ElapsedNS
		}
		f.Summary = Summarize(previous.Resource, f.Resource, previous.Runtime, f.Runtime, span)
		r.lastResource = f
		r.stats.LastResource = f.Resource
		r.stats.LastSummary = f.Summary
		r.stats.LastState = f.State
	}
	if f.Fact.ID != "" {
		r.stats.LastFact = f.Fact
	}
	r.addRing(Entry{r.header, f})
	r.stats.StoredFrames++
	raw, err := json.Marshal(f)
	if err != nil || len(raw)+1 > MaxLineBytes {
		r.stats.Invalid++
		return
	}
	if len(r.segment) == 0 {
		header, _ := json.Marshal(r.header)
		r.segment = append(header, '\n')
	}
	headerEnd := bytes.IndexByte(r.segment, '\n') + 1
	if len(r.segment)-headerEnd+len(raw)+1 > SegmentBytes-MaxHeaderBytes {
		r.flush(store)
		if r.dirty {
			r.stats.UnpersistedSegments++
		}
		r.slot = (r.slot + 1) % SegmentCount
		header, _ := json.Marshal(r.header)
		r.segment = append(header, '\n')
	}
	r.segment = append(r.segment, raw...)
	r.segment = append(r.segment, '\n')
	r.dirty = true
	r.maybePromote(f)
	if time.Since(r.lastPublished) >= time.Second {
		r.publish()
	}
}
func (r *Recorder) flush(store Storage) { r.flushAt(store, time.Now(), false) }

// All attempts, including errors, share the monotonic budget. Rotation can
// discard optional local context under a storm; that gap is persisted, never
// charged to the canonical signed journal or silently called complete.
func (r *Recorder) flushAt(store Storage, now time.Time, final bool) {
	if !r.dirty {
		return
	}
	if store.Write == nil {
		r.stats.Coverage = "MEMORY_ONLY"
		return
	}
	if final {
		if r.finalFlushed {
			r.stats.WriteThrottled++
			return
		}
		r.finalFlushed = true
		r.stats.ShutdownWrites++
	} else if !r.lastWriteAttempt.IsZero() && now.Sub(r.lastWriteAttempt) < 15*time.Second {
		r.stats.WriteThrottled++
		return
	}
	r.lastWriteAttempt = now
	h := r.header
	h.Gaps = ContextGaps{Dropped: r.dropped.Load(), UnpersistedSegments: r.stats.UnpersistedSegments, WriteFailures: r.stats.WriteFailures, WriteThrottled: r.stats.WriteThrottled}
	rawHeader, err := json.Marshal(h)
	if err != nil || len(rawHeader) > MaxHeaderBytes {
		r.stats.Coverage = "INVALID_HEADER"
		r.stats.Invalid++
		return
	}
	at := bytes.IndexByte(r.segment, '\n')
	if at < 0 {
		r.stats.Coverage = "INVALID_SEGMENT"
		r.stats.Invalid++
		return
	}
	raw := make([]byte, 0, len(rawHeader)+len(r.segment)-at)
	raw = append(raw, rawHeader...)
	raw = append(raw, r.segment[at:]...)
	if len(raw) > SegmentBytes {
		r.stats.Coverage = "INVALID_SEGMENT"
		r.stats.Invalid++
		return
	}
	started := time.Now()
	err = store.Write(r.slot, raw)
	r.stats.WriteNS += uint64(time.Since(started))
	r.stats.WriteAttemptBytes += uint64(len(raw))
	if err != nil {
		r.stats.WriteFailures++
		r.stats.Coverage = "WRITE_FAILED"
		return
	}
	r.stats.WriteBytes += uint64(len(raw))
	r.dirty = false
	r.stats.LastDurableAt = time.Now().UTC()
	r.stats.Coverage = "BOUNDED_LOCAL_WINDOW"
	if r.stats.UnpersistedSegments > 0 || r.stats.CorruptSegments > 0 || r.dropped.Load() > 0 {
		r.stats.Coverage = "PARTIAL_LOCAL_WINDOW"
	}
}
func (r *Recorder) promoteSample(f Frame, flag uint16, incident string, nowNS uint64) {
	if r.promote == nil {
		return
	}
	if nowNS < r.budgetStart || nowNS-r.budgetStart >= uint64(time.Minute) {
		r.budgetStart = nowNS
		r.budgetUsed = 0
	}
	if r.budgetUsed >= RemoteBudget {
		r.stats.RemoteSuppressed++
		return
	}
	r.budgetUsed++
	summary := f.Summary
	summary.Flags |= flag
	p := Promotion{At: f.Resource.At, Summary: summary, Incident: incident, PID: f.Resource.PID, Birth: f.Resource.Birth}
	if p.At.IsZero() {
		p.At = f.ObservedAt
	}
	if r.promote(p) {
		r.stats.RemotePromoted++
	} else {
		r.stats.PromotionQueueDropped++
	}
}
func (r *Recorder) maybePromote(f Frame) {
	if f.Resource.PID != 0 {
		if r.lastHeartbeat == 0 || f.ElapsedNS >= r.lastHeartbeat && f.ElapsedNS-r.lastHeartbeat >= uint64(time.Minute) {
			r.promoteSample(f, Heartbeat, "", f.ElapsedNS)
			r.lastHeartbeat = f.ElapsedNS
		}
		if r.postRemaining > 0 && f.ElapsedNS >= r.lastIncident && f.ElapsedNS <= r.postUntil && f.Resource.At.After(r.incidentAt) && !f.Resource.At.After(r.stats.PostWindowUntil) {
			r.promoteSample(f, ContextPost, r.incident, f.ElapsedNS)
			r.postRemaining--
		}
		return
	}
	e := f.Fact
	// A WER report, silence, a missing process or an unavailable sampler never
	// becomes a crash. This merely freezes context around a recorded failure.
	trigger := e.State == "failed" || e.Observer == "SERVICE_OPERATION" || e.Observer == "CONTROL_OPERATION" && (e.Code != "REQUEST_BEGIN" && e.Code != "REQUEST_RETURNED") || e.Component == "TLS" && e.Observer == "WINDOWS_EVENT_LOG" && e.NativeCode != 0 || e.Observer == "WINDOWS_EVENT_LOG" && (e.Operation == "APPLICATION_FAULT" || e.Operation == "SERVICE_TERMINATION" || e.Operation == "SERVICE_START_FAILURE")
	if !trigger || e.ID == "" {
		return
	}
	age := f.ObservedAt.Sub(e.At)
	if age > 30*time.Second || age < -time.Second {
		r.stats.HistoricalIncidents++
		return
	}
	if r.lastIncident != 0 && (f.ElapsedNS < r.lastIncident || f.ElapsedNS-r.lastIncident < uint64(time.Minute)) {
		r.stats.RemoteSuppressed++
		return
	}
	r.lastIncident = f.ElapsedNS
	r.incident = e.Incident
	if r.incident == "" {
		r.incident = e.ID
	}
	r.incidentAt = e.At
	r.stats.PostWindowUntil = e.At.Add(30 * time.Second)
	remain := r.stats.PostWindowUntil.Sub(f.ObservedAt)
	r.postUntil = f.ElapsedNS + uint64(max(0, remain))
	r.postRemaining = 4
	var samples []Frame
	for i := 1; i <= r.ringCount && len(samples) < 4; i++ {
		v := r.ring[(r.ringHead+r.ringCount-i)%RingCapacity]
		if v.Header.Session == r.header.Session && v.Frame.Resource.PID != 0 && !v.Frame.Resource.At.After(e.At) && e.At.Sub(v.Frame.Resource.At) <= 2*time.Minute {
			samples = append(samples, v.Frame)
		}
	}
	for i := len(samples) - 1; i >= 0; i-- {
		r.promoteSample(samples[i], ContextPre, r.incident, f.ElapsedNS)
	}
	for i := 0; i < r.ringCount && r.postRemaining > 0; i++ {
		v := r.ring[(r.ringHead+i)%RingCapacity]
		if v.Header.Session == r.header.Session && v.Frame.Resource.PID != 0 && v.Frame.Resource.At.After(e.At) && !v.Frame.Resource.At.After(r.stats.PostWindowUntil) {
			r.promoteSample(v.Frame, ContextPost, r.incident, f.ElapsedNS)
			r.postRemaining--
		}
	}
}
