package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	windowsplatform "github.com/buzzmean/veliq/platform/windows"
)

func TestResourceObserveBoundedOptionsRejectBeforeSampling(t *testing.T) {
	for _, args := range [][]string{{"-duration", "0s"}, {"-duration", "16m"}, {"-interval", "1s"}, {"-interval", "61s"}, {"-pids", "0"}, {"-pids", "1,1"}, {"-pids", "1,2,3,4,5,6,7,8,9"}, {"-pids", "4294967296"}, {"-pids", "game.exe"}, {"unexpected"}} {
		if _, e := parseOptions(args, io.Discard); e == nil {
			t.Fatal("unsafe options accepted", args)
		}
	}
	o, e := parseOptions([]string{"-pids", "123,456", "-duration", "15m", "-interval", "60s"}, io.Discard)
	if e != nil || len(o.pids) != 2 || o.duration != 15*time.Minute {
		t.Fatal(o, e)
	}
}

type testObserver struct {
	cancel context.CancelFunc
	calls  *int
}

func (t testObserver) Observe() windowsplatform.ResourceObservation {
	*t.calls++
	t.cancel()
	return windowsplatform.ResourceObservation{}
}
func TestResourceObserveCancellationBoundAndHonestFPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	calls := 0
	if e := collect(ctx, options{pids: []uint32{123, 456}, duration: time.Minute, interval: 5 * time.Second}, &out, func(uint32) observer { return testObserver{cancel: cancel, calls: &calls} }); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("collection continued after cancellation", calls)
	}
	dec := json.NewDecoder(&out)
	var meta map[string]any
	if e := dec.Decode(&meta); e != nil || meta["fps_status"] != "UNKNOWN_NO_FRAME_TIME_SOURCE" {
		t.Fatal(meta, e)
	}
	if !strings.Contains(meta["cpu_unit"].(string), "cores_consumed") {
		t.Fatal("CPU meaning ambiguous")
	}
}
func TestResourceObserveCanceledContextDoesNotTouchProcesses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if e := collect(ctx, options{pids: []uint32{123}, duration: time.Minute, interval: 5 * time.Second}, &out, func(uint32) observer { t.Fatal("process touched after cancellation"); return nil }); e != nil || out.Len() != 0 {
		t.Fatal(e, out.String())
	}
}

func TestResourceObserveInvalidArgumentsNeverEchoPrivateValues(t *testing.T) {
	for _, args := range [][]string{{"-duration", "PRIVATE_INVALID_VALUE"}, {"-PRIVATE_UNKNOWN_FLAG", "ignored"}, {"-interval", "PRIVATE_INVALID_VALUE"}} {
		var output bytes.Buffer
		_, e := parseOptions(args, &output)
		if e == nil || strings.Contains(output.String(), "PRIVATE_") || strings.Contains(e.Error(), "PRIVATE_") {
			t.Fatal("raw argument escaped sanitization")
		}
	}
}
