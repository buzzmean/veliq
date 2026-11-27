package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/flightrecorder"
	"github.com/buzzmean/veliq/core/security"
)

func flightViewFixture(s flightrecorder.Summary) clubhealth.Diagnostic {
	return clubhealth.Diagnostic{Component: "PERFORMANCE", Observer: "FLIGHT_RECORDER", Code: "RESOURCE_CONTEXT", Operation: s.Encode(), ProcessVerified: true, PID: 123, Birth: 134402359570643174, App: "veliq-service.exe"}
}
func TestFlightDiagnosticSummaryKnownUnitsOneCoreAndContext(t *testing.T) {
	s := flightrecorder.Summary{Flags: flightrecorder.KnownCPU | flightrecorder.KnownInterval | flightrecorder.KnownWorkingSet | flightrecorder.KnownIO | flightrecorder.KnownGC | flightrecorder.VerifiedProcess | flightrecorder.ContextPre | flightrecorder.ContextPost | flightrecorder.Heartbeat, SpanMS: 5000, CPUTimeUS: 10000000, WorkingSetKiB: 524288, ReadKiB: 12, WriteKiB: 34, GCPauseUS: 123}
	text := flightDiagnosticSummary(flightViewFixture(s))
	for _, part := range []string{"интервал 5000 мс", "CPU: 200.00% одного ядра (10000000 мкс)", "RSS: 512.00 МиБ", "IO: чтение 12 КиБ, запись 34 КиБ", "паузы GC: 123 мкс", "связь с поколением процесса подтверждена", "до события, после события, периодический снимок", "FPS не измерен; причина сбоя не установлена"} {
		if !strings.Contains(text, part) {
			t.Fatal("missing known-only presentation", part, text)
		}
	}
}
func TestFlightDiagnosticSummaryUnknownResetAndZeroInterval(t *testing.T) {
	for _, tc := range []struct {
		name         string
		s            flightrecorder.Summary
		want, absent []string
	}{
		{name: "unknown", s: flightrecorder.Summary{}, want: []string{"CPU: неизвестно", "RSS: неизвестно", "IO: неизвестно", "паузы GC: неизвестно", "интервал неизвестен", "тип контекста неизвестен"}, absent: []string{"0.00%", "RSS: 0.00"}},
		{name: "known-zero", s: flightrecorder.Summary{Flags: flightrecorder.KnownCPU | flightrecorder.KnownInterval, SpanMS: 5000}, want: []string{"CPU: 0.00% одного ядра (0 мкс)"}},
		{name: "reset", s: flightrecorder.Summary{Flags: flightrecorder.CounterReset | flightrecorder.KnownWorkingSet, WorkingSetKiB: 1024}, want: []string{"сброс или разрыв счётчиков", "дельты CPU/IO/GC неизвестны", "RSS: 1.00 МиБ", "CPU: неизвестно"}, absent: []string{"0.00%", "перезапуск"}},
		{name: "submillisecond", s: flightrecorder.Summary{Flags: flightrecorder.KnownCPU | flightrecorder.KnownInterval, CPUTimeUS: 10}, want: []string{"интервал меньше 1 мс", "CPU: 10 мкс; доля одного ядра неизвестна"}, absent: []string{"+Inf", "NaN", "% одного"}},
		{name: "no-interval", s: flightrecorder.Summary{Flags: flightrecorder.KnownCPU, CPUTimeUS: 100}, want: []string{"CPU: 100 мкс; доля одного ядра неизвестна"}, absent: []string{"% одного"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := flightDiagnosticSummary(flightViewFixture(tc.s))
			for _, part := range tc.want {
				if !strings.Contains(text, part) {
					t.Fatal(part, text)
				}
			}
			for _, part := range tc.absent {
				if strings.Contains(text, part) {
					t.Fatal("invented known quantity", part, text)
				}
			}
		})
	}
}
func TestFlightDiagnosticSummarySaturationNeverComputesFalseExactRatio(t *testing.T) {
	s := flightrecorder.Summary{Flags: flightrecorder.KnownCPU | flightrecorder.KnownInterval | flightrecorder.KnownWorkingSet | flightrecorder.KnownIO | flightrecorder.KnownGC | flightrecorder.Saturated, SpanMS: math.MaxUint32, CPUTimeUS: math.MaxUint32, WorkingSetKiB: math.MaxUint32, ReadKiB: math.MaxUint32, WriteKiB: 1, GCPauseUS: math.MaxUint32}
	text := flightDiagnosticSummary(flightViewFixture(s))
	if !strings.Contains(text, "насыщение формата") || !strings.Contains(text, "точные значения и доли не определяются") || strings.Contains(text, "% одного") || strings.Contains(text, "4294967295 мкс") {
		t.Fatal("saturated bound represented as exact", text)
	}
}
func TestFlightDiagnosticSummaryRequiresExactScopeAndCanonicalPayload(t *testing.T) {
	valid := flightViewFixture(flightrecorder.Summary{Flags: flightrecorder.Heartbeat})
	for _, change := range []func(*clubhealth.Diagnostic){func(e *clubhealth.Diagnostic) { e.Component = "TLS" }, func(e *clubhealth.Diagnostic) { e.Observer = "WINDOWS_EVENT_LOG" }, func(e *clubhealth.Diagnostic) { e.Code = "RECORDER_OVERFLOW" }, func(e *clubhealth.Diagnostic) { e.Operation = "FR1_invalid" }, func(e *clubhealth.Diagnostic) { e.Operation = strings.ToLower(e.Operation) }, func(e *clubhealth.Diagnostic) { e.Operation = flightrecorder.Summary{Flags: 0x8000}.Encode() }, func(e *clubhealth.Diagnostic) { e.Operation = flightrecorder.Summary{CPUTimeUS: 1}.Encode() }, func(e *clubhealth.Diagnostic) {
		e.Operation = flightrecorder.Summary{Flags: flightrecorder.CounterReset | flightrecorder.KnownCPU}.Encode()
	}} {
		e := valid
		change(&e)
		if text := flightDiagnosticSummary(e); text != "" {
			t.Fatal("out-of-scope/malformed payload decoded", e.Component, e.Observer, e.Code, text)
		}
	}
	valid.Code = "RECORDER_HEARTBEAT"
	if text := flightDiagnosticSummary(valid); !strings.Contains(text, "периодический снимок") {
		t.Fatal(text)
	}
	valid.ProcessVerified = false
	valid.Operation = flightrecorder.Summary{Flags: flightrecorder.VerifiedProcess}.Encode()
	if text := flightDiagnosticSummary(valid); !strings.Contains(text, "процесса не подтверждена") {
		t.Fatal("payload flag replaced identity evidence", text)
	}
}
func TestFlightDiagnosticTemplateEscapesAndKeepsOriginalOperation(t *testing.T) {
	e := flightViewFixture(flightrecorder.Summary{Flags: flightrecorder.KnownCPU | flightrecorder.KnownInterval, SpanMS: 5000, CPUTimeUS: 100000})
	e.PC = `<script>alert("pc")</script>`
	e.App = `<img src=x onerror="alert(1)">`
	render := func(e clubhealth.Diagnostic) string {
		var out bytes.Buffer
		if err := diagnosticView.Execute(&out, map[string]any{"Events": []map[string]any{{"Summary": e}}}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	html := render(e)
	if !strings.Contains(html, e.Operation) || !strings.Contains(html, "CPU: 2.00% одного ядра") || strings.Contains(html, "<script>") || strings.Contains(html, "<img ") || !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("template escaping/raw operation changed", html)
	}
	e.Operation = `<script>alert("operation")</script>`
	html = render(e)
	if strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") || strings.Contains(html, "CPU:") {
		t.Fatal("malformed operation produced decoded claim or unescaped HTML", html)
	}
}

func TestFlightDiagnosticOwnerHTMLThroughSignedStorageDoesNotCrossACL(t *testing.T) {
	a, s, mail := accountAPI(t, true)
	ownerID, device, key := persistentDeviceFixture(t, s, "PC13")
	otherID, _, _ := persistentDeviceFixture(t, s, "PC14")
	batch := persistentFixtureBatch("PC13")
	event := batch.Events[0]
	summary := flightrecorder.Summary{Flags: flightrecorder.KnownCPU | flightrecorder.KnownInterval | flightrecorder.ContextPre, SpanMS: 5000, CPUTimeUS: 10000000}
	event.Component, event.Observer, event.Code, event.Operation = "PERFORMANCE", "FLIGHT_RECORDER", "RESOURCE_CONTEXT", summary.Encode()
	batch.Events[0] = event
	proof, e := security.NewProof(device, batch.Audience(), key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(clubhealth.PersistentRequest{Batch: batch, Proof: proof})
	stored := httptest.NewRecorder()
	a.Handler().ServeHTTP(stored, httptest.NewRequest("POST", clubhealth.PersistentEndpoint, bytes.NewReader(raw)))
	var receipt clubhealth.Receipt
	if stored.Code != 200 || json.Unmarshal(stored.Body.Bytes(), &receipt) != nil || !receipt.Accepts(batch) {
		t.Fatal("signedFR1notdurablyaccepted", stored.Code)
	}
	owner, other := &call{api: a}, &call{api: a}
	login(t, owner, mail, ownerID+"@example.test")
	login(t, other, mail, otherID+"@example.test")
	for _, tc := range []struct {
		name, cookie string
		allowed      bool
		wantStatus   int
	}{{"owner", owner.cookie, true, 200}, {"other", other.cookie, false, 200}, {"anonymous", "", false, 401}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/account/diagnostics/view?pc=PC13", nil)
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			if w.Code != tc.wantStatus {
				t.Fatal(w.Code, w.Body.String())
			}
			contains := strings.Contains(w.Body.String(), "CPU: 200.00% одного ядра") && strings.Contains(w.Body.String(), summary.Encode())
			if contains != tc.allowed {
				t.Fatal("resource viewowner boundary violated", tc.name, w.Code)
			}
			if !tc.allowed && (strings.Contains(w.Body.String(), summary.Encode()) || strings.Contains(w.Body.String(), "RESOURCE_CONTEXT")) {
				t.Fatal("rawoperation leaked acrossownerboundary")
			}
		})
	}
	// Reading the HTML view never mutates the stored, signed operation.
	var saved string
	if e := s.DB.QueryRow(context.Background(), "SELECT summary->>'operation' FROM club_health_persistent_events WHERE device_id=$1 AND event_id=$2", device, event.ID).Scan(&saved); e != nil || saved != event.Operation {
		t.Fatal("HTMLreadchangedcanonicalpayload", e)
	}
}
