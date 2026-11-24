// An ordinary application socket: routing is performed by the Windows service, never this executable.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/buzzmean/veliq/internal/e2eprobe"
	windowsplatform "github.com/buzzmean/veliq/platform/windows"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Report struct {
	PID                   uint32 `json:"pid"`
	Exe                   string `json:"exe"`
	CreationTime          uint64 `json:"creation_time"`
	Destination           string `json:"destination"`
	Run                   string `json:"run_id"`
	Sent, Received        uint64
	RTTMS, JitterMS, Loss float64
	ObservedSources       []string  `json:"observed_sources"`
	MeasurementStarted    time.Time `json:"measurement_started"`
	MeasurementFinished   time.Time `json:"measurement_finished"`
	Warmup                *Report   `json:"warmup,omitempty"`
	Error                 string    `json:"error,omitempty"`
}

func run(target netip.AddrPort, key []byte, count int, interval, timeout time.Duration, quiet bool) (Report, error) {
	return runWithWarmup(target, key, count, 0, interval, timeout, quiet)
}

func runWithWarmup(target netip.AddrPort, key []byte, count, warmup int, interval, timeout time.Duration, quiet bool) (Report, error) {
	conn, e := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(target))
	if e != nil {
		return Report{}, e
	}
	defer conn.Close()
	var warm *Report
	if warmup > 0 {
		w, err := runPhase(conn, target, key, warmup, interval, timeout, quiet)
		warm = &w
		if err != nil {
			return Report{Warmup: warm}, fmt.Errorf("warm-up: %w", err)
		}
	}
	r, err := runPhase(conn, target, key, count, interval, timeout, quiet)
	r.Warmup = warm
	return r, err
}

func runPhase(conn *net.UDPConn, target netip.AddrPort, key []byte, count int, interval, timeout time.Duration, quiet bool) (Report, error) {
	exe, e := os.Executable()
	if e != nil {
		return Report{}, e
	}
	exe, _ = filepath.Abs(exe)
	r := Report{PID: uint32(os.Getpid()), Exe: exe, Destination: target.String(), ObservedSources: []string{}}
	if id, err := windowsplatform.NewDiscovery().Lookup(r.PID); err == nil {
		r.CreationTime = id.CreationTime
		r.Exe = id.Path
	}
	var runID [16]byte
	if _, e = rand.Read(runID[:]); e != nil {
		return r, e
	}
	r.Run = hex.EncodeToString(runID[:])
	var mu sync.Mutex
	sent := map[uint32]time.Time{}
	received := map[uint32]bool{}
	peers := map[string]bool{}
	total, jitter, previous := time.Duration(0), time.Duration(0), time.Duration(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, e2eprobe.Size+1)
		for {
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := conn.Read(buffer)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			p, err := e2eprobe.Decode(buffer[:n], key)
			if err != nil || !p.Reply || p.Run != runID {
				continue
			}
			mu.Lock()
			at, exists := sent[p.Sequence]
			if exists && !received[p.Sequence] {
				received[p.Sequence] = true
				r.Received++
				rtt := time.Since(at)
				total += rtt
				if previous != 0 {
					delta := rtt - previous
					if delta < 0 {
						delta = -delta
					}
					jitter += delta
				}
				previous = rtt
				peers[p.Peer.Addr().String()] = true
				if !quiet {
					fmt.Printf("received sequence=%d RTT=%.2fms echo_observed_source=%s\n", p.Sequence, float64(rtt)/1e6, p.Peer)
				}
			}
			mu.Unlock()
		}
	}()
	r.MeasurementStarted = time.Now().UTC()
	for i := 1; i <= count; i++ {
		seq := uint32(i)
		mu.Lock()
		sent[seq] = time.Now()
		mu.Unlock()
		if _, e = conn.Write(e2eprobe.Encode(e2eprobe.Packet{Run: runID, Sequence: seq}, key)); e != nil {
			cancel()
			conn.Close()
			<-done
			return r, e
		}
		mu.Lock()
		r.Sent++
		mu.Unlock()
		if !quiet {
			fmt.Printf("sent sequence=%d destination=%s\n", seq, target)
		}
		time.Sleep(interval)
	}
	r.MeasurementFinished = time.Now().UTC()
	time.Sleep(timeout)
	cancel()
	<-done
	if r.Received > 0 {
		r.RTTMS = float64(total) / float64(r.Received) / 1e6
	}
	if r.Received > 1 {
		r.JitterMS = float64(jitter) / float64(r.Received-1) / 1e6
	}
	r.Loss = 1 - float64(r.Received)/float64(r.Sent)
	for p := range peers {
		r.ObservedSources = append(r.ObservedSources, p)
	}
	sort.Strings(r.ObservedSources)
	if r.Received == 0 {
		return r, errors.New("no authenticated UDP responses")
	}
	return r, nil
}
func main() {
	dst := flag.String("target", "", "literal IPv4:port")
	token := flag.String("token-file", "", "echo token file")
	warmup := flag.Int("warmup-count", 0, "unmeasured warm-up datagrams on the same socket, 0..100")
	count := flag.Int("count", 100, "datagrams, 1..100000")
	interval := flag.Duration("interval", 100*time.Millisecond, "minimum 20ms")
	timeout := flag.Duration("timeout", time.Second, "final response grace, max10s")
	out := flag.String("report", "", "JSON report path")
	quiet := flag.Bool("quiet", false, "omit per-packet sequence output")
	flag.Parse()
	target, e := netip.ParseAddrPort(*dst)
	if e != nil || !target.Addr().Is4() || target.Port() == 0 || *warmup < 0 || *warmup > 100 || *count < 1 || *count > 100000 || *interval < 20*time.Millisecond || *timeout <= 0 || *timeout > 10*time.Second {
		fmt.Fprintln(os.Stderr, "invalid target or bounded probe parameters")
		os.Exit(2)
	}
	key, e := e2eprobe.Token(*token)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	r, e := runWithWarmup(target, key, *count, *warmup, *interval, *timeout, *quiet)
	if e != nil {
		r.Error = e.Error()
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	if *out != "" {
		if err := os.WriteFile(*out, b, 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	fmt.Println(string(b))
	if e != nil {
		os.Exit(1)
	}
}
