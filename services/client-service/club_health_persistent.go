package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/releaseinfo"
	wp "github.com/buzzmean/veliq/platform/windows"
)

type diagnosticInput struct {
	event clubhealth.Diagnostic
	key   string
}

func (c *Controller) observeProxyDiagnostic(r browserproxy.Record) {
	d := c.diagnostics.Load()
	if d == nil {
		return
	}
	switch r.Result {
	case "ORIGIN_PLAN_FAILED", "UPSTREAM_OPEN_FAILED", "HTTP_WRITE_FAILED", "HTTP_READ_FAILED", "DIRECT_MIDSTREAM_STALL":
	case "TUNNEL_ENDED":
		if r.ErrorCode == "" {
			return
		}
	default:
		return
	}
	e := d.event("OWNER_PROXY", "PROXY_EXCHANGE", "observed", r.Result)
	if r.ErrorCode != "" {
		e.Code = r.ErrorCode
	}
	e.NativeCode = r.NativeCode
	e.Operation = r.ErrorOperation
	e.PID, e.Birth = r.Owner.PID, r.Owner.Birth
	name := strings.ToLower(filepath.Base(r.Owner.Exe))
	if clubhealth.ValidApp(name) {
		e.App = name
		e.ProcessVerified = e.PID != 0 && e.Birth != 0
	}
	d.offer(e, "")
}

// ObserveDiagnosticError only accepts an internal fixed operation label.
func (c *Controller) ObserveDiagnosticError(operation string, err error) {
	if d := c.diagnostics.Load(); d != nil && err != nil {
		code, native := clubhealth.ErrorCode(err)
		d.note(operation, "SERVICE_OPERATION", "observed", code, native, "")
	}
}

type diagnosticUpload struct {
	batch   clubhealth.Batch
	receipt clubhealth.Receipt
	device  string
	reply   chan clubhealth.Batch
}
type diagnosticStatus struct {
	PC            string                  `json:"pc"`
	Version       string                  `json:"version"`
	Pending       int                     `json:"pending"`
	Lost          uint64                  `json:"lost"`
	Storage       string                  `json:"storage"`
	RetentionDays int                     `json:"retention_days"`
	MaxBytes      int                     `json:"max_bytes"`
	Events        []clubhealth.Diagnostic `json:"events"`
}
type persistentDiagnostics struct {
	done    chan struct{}
	write   func([]byte) error // Isolated fixture only; never configured through IPC.
	input   chan diagnosticInput
	uploads chan diagnosticUpload
	dropped atomic.Uint64
	cp      atomic.Pointer[controlclient.Client]
	status  atomic.Pointer[diagnosticStatus]
	base    clubhealth.Diagnostic
}

func (d *persistentDiagnostics) event(component, observer, state, code string) clubhealth.Diagnostic {
	e := d.base
	e.ID, _ = security.NewID()
	e.At = time.Now().UTC()
	e.Component, e.Observer, e.State, e.Code = component, observer, state, code
	return e
}
func (d *persistentDiagnostics) offer(e clubhealth.Diagnostic, key string) {
	select {
	case d.input <- diagnosticInput{e, key}:
	default:
		d.dropped.Add(1)
	}
}
func (d *persistentDiagnostics) note(component, observer, state, code string, native uint32, key string) {
	e := d.event(component, observer, state, code)
	e.NativeCode = native
	d.offer(e, key)
}

// ConfigurePersistentDiagnostics is called before slow activation/CP startup.
// It only starts independent metadata workers; routing and IPC never await disk.
func (c *Controller) ConfigurePersistentDiagnostics(m Manifest) {
	if m.StateDirectory == "" || !filepath.IsAbs(m.StateDirectory) || c.diagnostics.Load() != nil {
		return
	}
	pc, _ := os.Hostname()
	session, _ := security.NewID()
	source := releaseinfo.Current("client-service", nil, 0, 0).Commit
	if source == "" {
		source = "unknown"
	}
	d := &persistentDiagnostics{done: make(chan struct{}), input: make(chan diagnosticInput, clubhealth.InputEvents), uploads: make(chan diagnosticUpload, 1),
		base: clubhealth.Diagnostic{PC: pc, Version: "0.3." + BuildSequence, Source: source, Session: session, ServicePID: uint32(os.Getpid())}}
	if !c.diagnostics.CompareAndSwap(nil, d) {
		return
	}
	var identity struct {
		ID string `json:"id"`
	}
	if f, err := os.Open(m.DeviceIdentityFile); err == nil {
		info, err := f.Stat()
		if err == nil && info.Size() < 64*1024 {
			_ = json.NewDecoder(f).Decode(&identity)
		}
		f.Close()
	}
	go d.run(c.ctx, filepath.Join(m.StateDirectory, "club-health-journal.json"), identity.ID)
	go d.upload(c.ctx)
	go c.observeDiagnosticLocal(c.ctx, d)
	go c.observeDiagnosticWindows(c.ctx, d)
	go d.observeInternet(c.ctx)
	d.note("SERVICE", "SERVICE_LIFECYCLE", "ready", "SERVICE_STARTED", 0, "service")
}

func (d *persistentDiagnostics) run(ctx context.Context, path, device string) {
	if d.done != nil {
		defer close(d.done)
	}
	j := clubhealth.LoadJournal(path, device, time.Now())
	if j.Lost > 0 {
		e := d.event("JOURNAL", "JOURNAL_READ", "observed", "PREVIOUS_EVENTS_LOST")
		e.Lost = j.Lost
		j.Add(e, time.Now())
	}
	if j.Open {
		j.Add(d.event("JOURNAL", "JOURNAL_READ", "unknown", "UNCLEAN_STOP_TAIL_MAY_BE_MISSING"), time.Now())
	}
	j.Open = true
	transitions := &j.Transitions
	dirty := true
	storage := "PENDING"
	write := func(raw []byte) error { return protectedActivationWrite(path, raw) }
	if d.write != nil {
		write = d.write
	}
	publish := func() {
		s := &diagnosticStatus{PC: d.base.PC, Version: d.base.Version, Lost: j.Lost, Storage: storage, RetentionDays: 14, MaxBytes: clubhealth.JournalBytes}
		for _, row := range j.Rows {
			if !row.Acked {
				s.Pending++
			}
		}
		for _, row := range j.Rows[max(0, len(j.Rows)-32):] {
			s.Events = append(s.Events, row.Event)
		}
		d.status.Store(s)
	}
	flush := func() bool {
		before, lost := len(j.Rows), j.Lost
		j.Trim(time.Now())
		dirty = dirty || before != len(j.Rows) || lost != j.Lost
		if !dirty && storage == "OK" {
			publish()
			return true
		}
		if err := j.Save(write); err != nil {
			e := d.event("JOURNAL", "JOURNAL_WRITE", "failed", "WRITE_FAILED")
			e.Code, e.NativeCode = clubhealth.ErrorCode(err)
			if event, changed := transitions.Observe("journal-write", e); changed {
				j.Add(event, time.Now())
			}
			dirty = true
			storage = "WRITE_FAILED"
			publish()
			return false
		}
		dirty = false
		if storage == "WRITE_FAILED" {
			e, _ := transitions.Observe("journal-write", d.event("JOURNAL", "JOURNAL_WRITE", "ready", "WRITE_OK"))
			j.Add(e, time.Now())
			dirty = true
		}
		storage = "OK"
		publish()
		return !dirty // Новое событие восстановления сначала попадёт на диск.
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	lastLost := j.Lost
	for {
		select {
		case <-ctx.Done():
			for draining := true; draining; {
				select {
				case in := <-d.input:
					j.Add(in.event, time.Now())
				default:
					draining = false
				}
			}
			j.Lost += d.dropped.Swap(0)
			j.Add(d.event("SERVICE", "SERVICE_LIFECYCLE", "observed", "SERVICE_STOP_REQUESTED"), time.Now())
			j.Open = false
			dirty = true
			flush()
			return
		case in := <-d.input:
			e := in.event
			if in.key != "" {
				var ok bool
				e, ok = transitions.Observe(in.key, e)
				if !ok {
					continue
				}
			}
			if j.Add(e, time.Now()) {
				dirty = true
			}
		case request := <-d.uploads:
			if request.device != "" && j.Device == "" {
				j.Device = request.device
				dirty = true
			}
			if request.device != j.Device {
				// Rotate at authenticated identity replacement. Old events are
				// never uploaded under the new owner/device; account the loss.
				if request.reply == nil {
					continue
				}
				lost := j.Lost
				for _, row := range j.Rows {
					if !row.Acked {
						lost++
					}
				}
				j = clubhealth.Journal{Format: 1, Device: request.device, Lost: lost, Open: true}
				transitions = &j.Transitions
				e := d.event("JOURNAL", "DEVICE_BINDING", "observed", "DEVICE_IDENTITY_CHANGED")
				e.Lost = lost
				j.Add(e, time.Now())
				dirty = true
			}
			if request.reply != nil {
				if flush() {
					request.reply <- j.Batch()
				} else {
					request.reply <- clubhealth.Batch{}
				}
			} else if j.Ack(request.batch, request.receipt) {
				dirty = true
				flush()
			}
		case <-ticker.C:
			if lost := d.dropped.Swap(0); lost > 0 {
				j.Lost += lost
				dirty = true
			}
			before := len(j.Rows)
			j.Trim(time.Now())
			dirty = dirty || before != len(j.Rows)
			if j.Lost != lastLost {
				e := d.event("JOURNAL", "BOUNDED_QUEUE", "observed", "EVENTS_LOST")
				e.Lost = j.Lost
				j.Add(e, time.Now())
				lastLost = j.Lost
				dirty = true
			}
			if dirty {
				flush()
			} else {
				publish()
			}
		}
	}
}

func (d *persistentDiagnostics) upload(ctx context.Context) {
	delay := 30 * time.Second
	for {
		// Session-specific deterministic jitter avoids a club-wide retry burst.
		jitter := time.Duration(d.base.Session[0]%11) * time.Second
		timer := time.NewTimer(delay + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		cp := d.cp.Load()
		if cp == nil {
			continue
		}
		reply := make(chan clubhealth.Batch, 1)
		select {
		case d.uploads <- diagnosticUpload{device: cp.DeviceID, reply: reply}:
		case <-ctx.Done():
			return
		}
		var b clubhealth.Batch
		select {
		case b = <-reply:
		case <-ctx.Done():
			return
		}
		if b.Protocol != 1 {
			continue
		}
		request, cancel := context.WithTimeout(ctx, 8*time.Second)
		receipt, err := cp.ClubHealthPersistent(request, b)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			code, native := clubhealth.ErrorCode(err)
			var status controlclient.DiagnosticHTTPError
			if errors.As(err, &status) {
				code = "HTTP_STATUS"
				native = uint32(status.Status)
			}
			state := "failed"
			if native == 404 || native == 405 {
				code = "SERVER_PROTOCOL_UNAVAILABLE"
				state = "unknown"
			}
			d.note("CONTROL_PLANE", "AUTHENTICATED_UPLOAD", state, code, native, "cp")
			delay = min(5*time.Minute, delay*2)
			continue
		}
		d.note("CONTROL_PLANE", "AUTHENTICATED_UPLOAD", "ready", "DURABLE_ACK", 0, "cp")
		select {
		case d.uploads <- diagnosticUpload{device: cp.DeviceID, batch: b, receipt: receipt}:
		case <-ctx.Done():
			return
		}
		delay = 30 * time.Second
		if len(b.Events) == clubhealth.MaxEvents {
			delay = 5 * time.Second
		}
	}
}

func (c *Controller) observeDiagnosticLocal(ctx context.Context, d *persistentDiagnostics) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		c.mu.Lock()
		enabled, startError := c.enabled, c.captureStartError
		c.mu.Unlock()
		state, code := "unknown", "CAPTURE_OFF"
		if c.Backend != nil {
			s := c.Backend.Status()
			if enabled && s.Ready {
				state, code = "ready", "CAPTURE_READY"
			} else if enabled && (s.Error != "" || startError != "") {
				state, code = "failed", "CAPTURE_FAILED"
			}
		}
		d.note("CAPTURE", "CAPTURE_BACKEND", state, code, 0, "capture")
		// Snapshot comes from each real owned listener, not a configured port string.
		if a := c.browser.authority.published.Load(); a != nil {
			for _, p := range a.listeners {
				endpoint, err := netip.ParseAddrPort(p.Address)
				if err != nil {
					continue
				}
				e := d.event("OWNER_PROXY", "LISTENER", "failed", "NOT_LISTENING")
				e.Port = endpoint.Port()
				if p.Server != nil {
					s := p.Server.Snapshot()
					if s.Listening {
						e.State, e.Code = "ready", "LISTENING"
					}
				}
				d.offer(e, fmt.Sprintf("listener:%d", e.Port))
			}
		}
		c.mu.Lock()
		pools := make([]*transport.Pool, 0, len(c.relayPools))
		for _, p := range c.relayPools {
			pools = append(pools, p)
		}
		c.mu.Unlock()
		var samples []transport.PoolSnapshot
		for _, p := range pools {
			samples = append(samples, p.Snapshot())
		}
		state, code = diagnosticRelayHealth(samples, time.Now())
		d.note("RELAY", "AUTHENTICATED_TRANSPORT", state, code, 0, "relay")
	}
}

func diagnosticRelayHealth(samples []transport.PoolSnapshot, now time.Time) (string, string) {
	state, code := "unknown", "NO_AUTHENTICATED_SESSION"
	for _, s := range samples {
		if s.HealthySessions > 0 {
			return "ready", "AUTHENTICATED_SESSION"
		}
		for _, open := range s.RecentOpens {
			if !open.At.After(now) && now.Sub(open.At) <= 2*time.Minute && open.FailureReason != "" {
				state, code = "failed", "RECENT_OPEN_FAILED"
				reason := strings.ToUpper(open.FailureReason)
				if clubhealth.ValidReason(reason) {
					code = reason
				}
			}
		}
	}
	return state, code
}

func (c *Controller) observeDiagnosticWindows(ctx context.Context, d *persistentDiagnostics) {
	since := time.Now().Add(-15 * time.Minute)
	d.note("WINDOWS", "WINDOWS_EVENT_LOG", "observed", "STARTUP_HISTORY_LIMIT_15_MINUTES", 0, "")
	for {
		started := time.Now()
		rows, err := wp.DiagnosticWindowsEvents(since)
		service := wp.DiagnosticLanGameState()
		base := d.event(service.Component, service.Observer, service.State, service.Code)
		service.ID, service.At = base.ID, base.At
		service.PC, service.Version, service.Source, service.Session, service.ServicePID = d.base.PC, d.base.Version, d.base.Source, d.base.Session, d.base.ServicePID
		d.offer(service, "langame")
		for _, e := range rows {
			e.PC, e.Version, e.Source, e.Session, e.ServicePID = d.base.PC, d.base.Version, d.base.Source, d.base.Session, d.base.ServicePID
			d.offer(e, "")
		}
		if err != nil {
			code, native := clubhealth.ErrorCode(err)
			d.note("WINDOWS", "WINDOWS_EVENT_LOG", "unknown", code, native, "windows")
		}
		if err == nil {
			d.note("WINDOWS", "WINDOWS_EVENT_LOG", "ready", "QUERY_OK", 0, "windows")
		}
		var incomplete bool
		since, incomplete = diagnosticNextWindow(since, started, err)
		if incomplete {
			d.note("WINDOWS", "WINDOWS_EVENT_LOG", "unknown", "HISTORY_WINDOW_INCOMPLETE", 0, "windows-history")
		}
		timer := time.NewTimer(15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Повторяем неудачное чтение, но не расширяем окно бесконечно при отказе журнала.
func diagnosticNextWindow(since, started time.Time, err error) (time.Time, bool) {
	if err == nil {
		return started.Add(-time.Second), false
	}
	oldest := started.Add(-15 * time.Minute)
	if since.Before(oldest) {
		return oldest, true
	}
	return since, true
}

func (d *persistentDiagnostics) observeInternet(ctx context.Context) {
	// Direct service traffic is excluded from capture. This is a reachability
	// observation, not proof that every Internet route works or VELIQ is at fault.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		for index, target := range []string{"https://www.microsoft.com/", "https://www.mozilla.org/"} {
			req, err := http.NewRequestWithContext(ctx, "HEAD", target, nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			state, code, native := "ready", "HTTPS_RESPONSE", uint32(0)
			if err != nil {
				state = "failed"
				code, native = clubhealth.ErrorCode(err)
			} else {
				native = uint32(res.StatusCode)
				res.Body.Close()
			}
			d.note("INTERNET", fmt.Sprintf("DIRECT_HTTPS_%d", index+1), state, code, native, fmt.Sprintf("internet:%d", index))
		}
		timer := time.NewTimer(time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
