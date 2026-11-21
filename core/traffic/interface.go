package traffic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ReadInterface samples Linux kernel NIC TX (including non-relay traffic and
// transport overhead). No capture, network query, driver change or credentials.
func ReadInterface(relay, iface string, now time.Time) (Observation, error) {
	if iface == "" {
		raw, e := os.ReadFile("/proc/net/route")
		if e != nil {
			return Observation{}, errors.New("TRAFFIC_DEFAULT_INTERFACE_UNAVAILABLE")
		}
		best := uint64(^uint32(0))
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) < 8 || f[1] != "00000000" {
				continue
			}
			flags, err := strconv.ParseUint(f[3], 16, 32)
			if err != nil || flags&1 == 0 {
				continue
			}
			metric, e := strconv.ParseUint(f[6], 10, 32)
			if e == nil && metric < best {
				iface = f[0]
				best = metric
			}
		}
	}
	if iface == "" || iface == "lo" || iface == "." || iface == ".." || len(iface) > 64 || filepath.Base(iface) != iface || strings.ContainsAny(iface, "\\\x00") {
		return Observation{}, errors.New("TRAFFIC_INTERFACE_INVALID")
	}
	raw, e := os.ReadFile(filepath.Join("/sys/class/net", iface, "statistics/tx_bytes"))
	if e != nil {
		return Observation{}, errors.New("TRAFFIC_INTERFACE_COUNTER_UNAVAILABLE")
	}
	counter, e := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if e != nil {
		return Observation{}, errors.New("TRAFFIC_INTERFACE_COUNTER_INVALID")
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return Observation{}, errors.New("TRAFFIC_BOOT_EPOCH_UNAVAILABLE")
	}
	hash := sha256.Sum256(boot)
	stat, e := os.ReadFile("/proc/stat")
	if e != nil {
		return Observation{}, errors.New("TRAFFIC_BOOT_TIME_UNAVAILABLE")
	}
	var bootAt time.Time
	for _, line := range strings.Split(string(stat), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "btime" {
			n, e := strconv.ParseInt(f[1], 10, 64)
			if e == nil {
				bootAt = time.Unix(n, 0).UTC()
			}
			break
		}
	}
	if bootAt.IsZero() {
		return Observation{}, errors.New("TRAFFIC_BOOT_TIME_INVALID")
	}
	return Observation{Relay: relay, Interface: iface, Boot: hex.EncodeToString(hash[:]), BootAt: bootAt, At: now.UTC(), Counter: counter}, nil
}
