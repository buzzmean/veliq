//go:build linux

package windowsplatform

import (
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/buzzmean/veliq/core/flightrecorder"
)

func resourceProcFile(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 8192))
}

// Linux is an actual own-process counterpart for tests/benchmarks. Its IO bytes
// are /proc storage accounting; they are not labelled as Windows transfer bytes.
func readNativeResources(pid uint32) flightrecorder.ResourceSample {
	frame := flightrecorder.ResourceSample{PID: pid, Source: "LINUX_PROC_RUSAGE", ErrorCode: "RESOURCE_UNSUPPORTED"}
	if pid != uint32(os.Getpid()) {
		return frame
	}
	raw, e := resourceProcFile("/proc/self/stat")
	if e != nil {
		frame.ErrorCode = "RESOURCE_UNAVAILABLE"
		return frame
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return frame
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return frame
	}
	frame.Birth, _ = strconv.ParseUint(fields[19], 10, 64)
	if frame.Birth == 0 {
		return frame
	}
	frame.ErrorCode = "OK"
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) == nil {
		frame.CPUTimeNS = uint64(usage.Utime.Sec+usage.Stime.Sec)*1000000000 + uint64(usage.Utime.Usec+usage.Stime.Usec)*1000
		frame.Known |= flightrecorder.ResourceCPU
	}
	if threads, e := strconv.ParseUint(fields[17], 10, 32); e == nil {
		frame.Threads = uint32(threads)
		frame.Known |= flightrecorder.ResourceThreads
	}
	if raw, e = resourceProcFile("/proc/self/statm"); e == nil {
		f := strings.Fields(string(raw))
		if len(f) > 1 {
			if rss, e := strconv.ParseUint(f[1], 10, 64); e == nil {
				frame.WorkingSetBytes = rss * uint64(os.Getpagesize())
				frame.Known |= flightrecorder.ResourceWorkingSet
			}
		}
	}
	if raw, e = resourceProcFile("/proc/self/io"); e == nil {
		var read, write bool
		for _, line := range strings.Split(string(raw), "\n") {
			pair := strings.Fields(line)
			if len(pair) != 2 {
				continue
			}
			n, e := strconv.ParseUint(pair[1], 10, 64)
			if e != nil {
				continue
			}
			switch pair[0] {
			case "read_bytes:":
				frame.ReadBytes = n
				read = true
			case "write_bytes:":
				frame.WriteBytes = n
				write = true
			}
		}
		if read && write {
			frame.Known |= flightrecorder.ResourceIO
		}
	}
	return frame
}
