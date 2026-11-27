package controlplane

import (
	"fmt"
	"strings"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/flightrecorder"
)

// flightDiagnosticSummary only interprets the canonical resource envelope in
// its dedicated event scope. It returns ordinary text: html/template must keep
// escaping it. The original Operation remains visible and unchanged.
func flightDiagnosticSummary(e clubhealth.Diagnostic) string {
	if e.Component != "PERFORMANCE" || e.Observer != "FLIGHT_RECORDER" || (e.Code != "RESOURCE_CONTEXT" && e.Code != "RECORDER_HEARTBEAT") {
		return ""
	}
	s, ok := flightrecorder.Decode(e.Operation)
	if !ok {
		return ""
	}
	known := func(flag uint16) bool { return s.Flags&flag != 0 }
	saturated := known(flightrecorder.Saturated)
	parts := []string{"Ресурсы"}
	switch {
	case !known(flightrecorder.KnownInterval):
		parts = append(parts, "интервал неизвестен")
	case saturated:
		parts = append(parts, "интервал ограничен форматом")
	case s.SpanMS == 0:
		parts = append(parts, "интервал меньше 1 мс")
	default:
		parts = append(parts, fmt.Sprintf("интервал %d мс", s.SpanMS))
	}
	switch {
	case !known(flightrecorder.KnownCPU):
		parts = append(parts, "CPU: неизвестно")
	case saturated:
		parts = append(parts, "CPU: значение ограничено; доля одного ядра неизвестна")
	case !known(flightrecorder.KnownInterval) || s.SpanMS == 0:
		parts = append(parts, fmt.Sprintf("CPU: %d мкс; доля одного ядра неизвестна", s.CPUTimeUS))
	default:
		// One core may exceed100% when multiple threads run. This is never a
		// percentage of all CPUs and never a frame-time/FPS measurement.
		percent := float64(s.CPUTimeUS) / (float64(s.SpanMS) * 10)
		parts = append(parts, fmt.Sprintf("CPU: %.2f%% одного ядра (%d мкс)", percent, s.CPUTimeUS))
	}
	switch {
	case !known(flightrecorder.KnownWorkingSet):
		parts = append(parts, "RSS: неизвестно")
	case saturated:
		parts = append(parts, "RSS: значение ограничено")
	default:
		parts = append(parts, fmt.Sprintf("RSS: %.2f МиБ", float64(s.WorkingSetKiB)/1024))
	}
	switch {
	case !known(flightrecorder.KnownIO):
		parts = append(parts, "IO: неизвестно")
	case saturated:
		parts = append(parts, "IO: значения ограничены")
	default:
		parts = append(parts, fmt.Sprintf("IO: чтение %d КиБ, запись %d КиБ", s.ReadKiB, s.WriteKiB))
	}
	switch {
	case !known(flightrecorder.KnownGC):
		parts = append(parts, "паузы GC: неизвестно")
	case saturated:
		parts = append(parts, "паузы GC: значение ограничено")
	default:
		parts = append(parts, fmt.Sprintf("паузы GC: %d мкс", s.GCPauseUS))
	}
	if known(flightrecorder.CounterReset) {
		parts = append(parts, "сброс или разрыв счётчиков: дельты CPU/IO/GC неизвестны")
	}
	if saturated {
		parts = append(parts, "насыщение формата: точные значения и доли не определяются")
	}
	if known(flightrecorder.VerifiedProcess) && e.ProcessVerified && e.PID != 0 && e.Birth != 0 {
		parts = append(parts, "связь с поколением процесса подтверждена")
	} else {
		parts = append(parts, "связь с поколением процесса не подтверждена")
	}
	var context []string
	if known(flightrecorder.ContextPre) {
		context = append(context, "до события")
	}
	if known(flightrecorder.ContextPost) {
		context = append(context, "после события")
	}
	if known(flightrecorder.Heartbeat) {
		context = append(context, "периодический снимок")
	}
	if len(context) > 0 {
		parts = append(parts, "контекст: "+strings.Join(context, ", "))
	} else {
		parts = append(parts, "тип контекста неизвестен")
	}
	parts = append(parts, "FPS не измерен; причина сбоя не установлена")
	return strings.Join(parts, "; ")
}
