package windowsplatform

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const gameReplyPriority = -29500
const maxForeignGameHandles = 64

type reflectKey struct {
	Opened     uint64
	PID, Layer uint32
}
type reflectRecord struct {
	key      reflectKey
	flags    uint64
	priority int16
	filter   []byte
	matched  bool
}
type gameGuardState struct {
	mu                 sync.Mutex
	processAt          time.Time
	processObservation GameUDPGuardStatus
	ready              bool
	error              string
	foreign            map[reflectKey]*reflectRecord
}

func decodeGameReflect(a [80]byte, p []byte) (reflectRecord, byte, error) {
	if a[8] != 4 || (a[9] != 8 && a[9] != 9) {
		return reflectRecord{}, 0, errors.New("GAME_REFLECT_INVALID_EVENT")
	}
	d := a[16:]
	r := reflectRecord{key: reflectKey{binary.LittleEndian.Uint64(d[:8]), binary.LittleEndian.Uint32(d[8:12]), binary.LittleEndian.Uint32(d[12:16])}, flags: binary.LittleEndian.Uint64(d[16:24]), priority: int16(binary.LittleEndian.Uint16(d[24:26]))}
	if len(p) > 16*1024 {
		return r, a[9], errors.New("GAME_REFLECT_FILTER_BOUND")
	}
	r.filter = append(append([]byte(nil), p...), 0)
	return r, a[9], nil
}
func (g *gameGuardState) event(r reflectRecord, event byte, self uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.key.PID == self {
		if event == 8 && r.key.Layer == 0 && r.flags&1 != 0 && r.priority == gameReplyPriority && g.error == "" {
			g.ready = true
		}
		return
	}
	if r.key.Layer != 0 || r.flags&1 != 0 {
		return
	} // foreign observation does not modify packets
	if event == 9 {
		delete(g.foreign, r.key)
		return
	}
	if g.foreign == nil {
		g.foreign = map[reflectKey]*reflectRecord{}
	}
	if len(g.foreign) >= maxForeignGameHandles {
		g.ready = false
		g.error = "UDP_FOREIGN_HANDLE_LIMIT"
		return
	}
	g.foreign[r.key] = &r
}
func (g *gameGuardState) fail(code string) {
	g.mu.Lock()
	g.error = code
	g.ready = false
	g.mu.Unlock()
}
func (g *gameGuardState) snapshot() GameUDPGuardStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := GameUDPGuardStatus{Ready: g.ready, ForeignHandles: len(g.foreign), Error: g.error, ForeignPIDs: []uint32{}}
	seen := map[uint32]bool{}
	for _, h := range g.foreign {
		if h.matched {
			s.Conflict = true
		}
		if !seen[h.key.PID] {
			seen[h.key.PID] = true
			s.ForeignPIDs = append(s.ForeignPIDs, h.key.PID)
		}
	}
	return s
}

// The service polls guard status even while capture restarts. Never replace a
// struct containing a live mutex; reset its fields under the persistent lock.
func (g *gameGuardState) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ready = false
	g.error = ""
	g.foreign = map[reflectKey]*reflectRecord{}
	g.processAt = time.Time{}
	g.processObservation = GameUDPGuardStatus{}
}

// Toolhelp/SCM queries must never hold the packet-path guard lock. Concurrent
// readers use the last completed observation; startup remains pending. A scan
// begun before reset cannot publish into a new capture generation.
func (g *gameGuardState) processSnapshot(now time.Time, scan func() GameUDPGuardStatus) GameUDPGuardStatus {
	g.mu.Lock()
	if now.Sub(g.processAt) < time.Second {
		s := g.processObservation
		g.mu.Unlock()
		return s
	}
	first := g.processAt.IsZero()
	g.processAt = now
	if first {
		g.processObservation.Error = "GAME_PROCESS_CHECK_PENDING"
	}
	g.mu.Unlock()
	observation := scan()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.processAt.Equal(now) {
		g.processObservation = observation
	}
	return g.processObservation
}
