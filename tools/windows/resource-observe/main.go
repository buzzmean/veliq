// Resource-observe reads counters for explicit, already-running process IDs.
// It never launches, stops, attaches to, changes or discovers an application.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	windowsplatform "github.com/buzzmean/veliq/platform/windows"
)

type options struct {
	pids               []uint32
	duration, interval time.Duration
}

func parseOptions(args []string, out io.Writer) (options, error) {
	f := flag.NewFlagSet("resource-observe", flag.ContinueOnError)
	// The flag package normally echoes invalid raw values/flag names. Never do
	// that in a diagnostic collector: only fixed public error codes leave main.
	f.SetOutput(io.Discard)
	ids := f.String("pids", "", "Comma-separated existing PIDs (maximum 8); default is this collector only")
	duration := f.Duration("duration", time.Minute, "Passive observation window, 1s..15m")
	interval := f.Duration("interval", 5*time.Second, "Read interval, 5s..60s")
	if e := f.Parse(args); e != nil {
		return options{}, errors.New("invalid bounded measurement options")
	}
	if f.NArg() != 0 || *duration < time.Second || *duration > 15*time.Minute || *interval < 5*time.Second || *interval > time.Minute {
		return options{}, errors.New("invalid bounded measurement options")
	}
	o := options{duration: *duration, interval: *interval}
	if *ids == "" {
		o.pids = []uint32{uint32(os.Getpid())}
		return o, nil
	}
	parts := strings.Split(*ids, ",")
	if len(parts) > 8 {
		return options{}, errors.New("at most 8 explicit PIDs")
	}
	seen := map[uint32]bool{}
	for _, part := range parts {
		n, e := strconv.ParseUint(part, 10, 32)
		if e != nil || n == 0 || seen[uint32(n)] {
			return options{}, errors.New("PIDs must be distinct positive uint32 values")
		}
		seen[uint32(n)] = true
		o.pids = append(o.pids, uint32(n))
	}
	return o, nil
}

type observer interface {
	Observe() windowsplatform.ResourceObservation
}
type sampleRow struct {
	Type        string                              `json:"type"`
	Index       int                                 `json:"index"`
	Observation windowsplatform.ResourceObservation `json:"observation"`
}

func collect(ctx context.Context, o options, out io.Writer, factory func(uint32) observer) error {
	if len(o.pids) < 1 || len(o.pids) > 8 || o.duration < time.Second || o.duration > 15*time.Minute || o.interval < 5*time.Second || o.interval > time.Minute {
		return errors.New("invalid bounded measurement options")
	}
	ctx, cancel := context.WithTimeout(ctx, o.duration)
	defer cancel()
	if ctx.Err() != nil {
		return nil
	}
	enc := json.NewEncoder(out)
	// No credential, path, command line, network endpoint, user name, process
	// memory content, packet, game hook or synthetic FPS value is collected.
	if e := enc.Encode(struct {
		Type       string    `json:"type"`
		Schema     int       `json:"schema"`
		At         time.Time `json:"at"`
		DurationNS int64     `json:"duration_ns"`
		IntervalNS int64     `json:"interval_ns"`
		FPS        string    `json:"fps_status"`
		CPU        string    `json:"cpu_unit"`
	}{"metadata", 1, time.Now().UTC(), int64(o.duration), int64(o.interval), "UNKNOWN_NO_FRAME_TIME_SOURCE", "cpu_delta_ns / elapsed_ns = cores_consumed; not whole-PC percent"}); e != nil {
		return e
	}
	readers := make([]observer, len(o.pids))
	for i, pid := range o.pids {
		readers[i] = factory(pid)
	}
	index := 0
	for {
		for _, reader := range readers {
			if ctx.Err() != nil {
				return nil
			}
			if e := enc.Encode(sampleRow{Type: "resource", Index: index, Observation: reader.Observe()}); e != nil {
				return e
			}
		}
		index++
		timer := time.NewTimer(o.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
func main() {
	o, e := parseOptions(os.Args[1:], os.Stderr)
	if e != nil {
		fmt.Fprintln(os.Stderr, "RESOURCE_OPTIONS_INVALID")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if e = collect(ctx, o, os.Stdout, func(pid uint32) observer { return windowsplatform.NewResourceSampler(pid) }); e != nil {
		fmt.Fprintln(os.Stderr, "RESOURCE_COLLECTION_FAILED")
		os.Exit(1)
	}
}
