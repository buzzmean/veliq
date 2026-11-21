//go:build windows

package windowsplatform

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/routing"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var setTCPEntry = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetTcpEntry")

func queryOwnedTCP() ([]ownedTCPRow, error) {
	var size uint32
	r, _, _ := getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
	if uint32(r) != uint32(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("HOT_ATTACH TCP table sizing: %d", r)
	}
	for i := 0; i < 3; i++ {
		if size < 4 || size > 4+hotAttachLimit*24 {
			return nil, errors.New("HOT_ATTACH native table capacity")
		}
		b := make([]byte, size)
		r, _, _ = getTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
		if uint32(r) == uint32(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("HOT_ATTACH TCP table: %d", r)
		}
		return decodeOwnedTCP(b)
	}
	return nil, errors.New("HOT_ATTACH TCP table churn")
}

// Revalidate both owner and process birth immediately before exact-tuple deletion.
// Windows has no PID argument for SetTcpEntry; never delete from a cached row alone.
func resetOwnedTCP(row ownedTCPRow, id ProcessIdentity) error {
	if id.PID == 0 || id.PID == uint32(os.Getpid()) || !IsCurrent(id) {
		return errors.New("HOT_ATTACH stale/self identity")
	}
	rows, err := queryOwnedTCP()
	if err != nil {
		return err
	}
	for _, current := range rows {
		if current.Tuple == row.Tuple {
			if current.PID != id.PID {
				return errors.New("HOT_ATTACH owner changed")
			}
			if !IsCurrent(id) {
				return errors.New("HOT_ATTACH process birth changed")
			}
			binary.LittleEndian.PutUint32(current.raw[:4], 12) // MIB_TCP_STATE_DELETE_TCB
			result, _, _ := setTCPEntry.Call(uintptr(unsafe.Pointer(&current.raw[0])))
			if result != 0 {
				return fmt.Errorf("HOT_ATTACH SetTcpEntry: %d", result)
			}
			return nil
		}
	}
	return nil // already closed; never guess another tuple
}

// Capture established tuples before the policy/capture boundary. New SYNs are
// never added to this set by periodic reconciliation.
func (b *WinDivertBackend) snapshotHotTargets() {
	rows, err := queryOwnedTCP()
	targets := []hotAttachTarget{}
	identities := map[uint32]ProcessIdentity{}
	if err == nil {
		for _, row := range rows {
			if row.State < 5 || row.PID == 0 || row.PID == uint32(os.Getpid()) || (row.Tuple.Destination.Addr().IsLoopback() || row.Tuple.Source.Addr() == row.Tuple.Destination.Addr()) {
				continue
			}
			id, ok := identities[row.PID]
			if !ok {
				id, _ = b.cache.Lookup(row.PID)
				if id.PID != 0 && !IsCurrent(id) {
					id = ProcessIdentity{}
				}
				identities[row.PID] = id
			}
			if id.PID != 0 {
				targets = append(targets, hotAttachTarget{row, id})
			}
		}
	}
	b.hot.mu.Lock()
	b.hot.targets = targets
	b.hot.targetError = ""
	if err != nil {
		b.hot.targetError = err.Error()
	}
	b.hot.mu.Unlock()
}
func (b *WinDivertBackend) HotAttachStatus() HotAttachStatus { return b.hot.snapshot() }
func (b *WinDivertBackend) RequestHotAttach(reason string) {
	b.hot.begin(reason)
	b.policyEpoch.Add(1)
	select {
	case b.hotRequests <- struct{}{}:
	default:
	}
}

// Optional backward-compatible backend contract used by all routing edits.
// Existing proxy sockets close before publication; ingress and UDP sends/opens
// are fenced while policy changes. Unselected applications are never retired.
func (b *WinDivertBackend) Reconfigure(application string, change func() error) error {
	var ids []string
	if application != "" {
		ids = []string{application}
	}
	return b.ReconfigureApplications(ids, change)
}
func (b *WinDivertBackend) ReconfigureApplications(ids []string, change func() error) error {
	return b.reconfigureApplications(ids, change, false)
}

// Publish native browser policy with the same UDP ingress/send fence, retaining
// ALL established TCP sockets. Do not schedule a TCP-table reconnect sweep.
func (b *WinDivertBackend) ReconfigureNewConnections(application string, change func() error) error {
	return b.reconfigureApplications([]string{application}, change, true)
}
func (b *WinDivertBackend) reconfigureApplications(ids []string, change func() error, preserveTCP bool) error {
	b.life.Lock()
	defer b.life.Unlock()
	b.mu.Lock()
	active := b.dll != nil
	tcp := b.tcp
	b.mu.Unlock()
	if !active {
		return change()
	}
	affected := map[string]bool{}
	for _, id := range ids {
		affected[id] = true
	}
	// Phase 1 is short: fence only affected applications, detach their handles.
	// Waiting for I/O/abort/relay setup must not pause unrelated packet ingress.
	b.policyMu.Lock()
	b.transition = affected
	b.transitionAll = len(ids) == 0
	epoch := b.hot.snapshot().Epoch
	if !preserveTCP {
		epoch = b.hot.begin("policy_activation")
		b.hot.mu.Lock()
		b.hot.status.State = "HOT_ATTACH_PREPARING"
		b.hot.mu.Unlock()
	}
	sockets := []net.Conn{}
	pending := []<-chan struct{}{}
	datagrams := []routing.Datagram{}
	if tcp != nil && !preserveTCP {
		tcp.state.mu.Lock()
		for _, e := range tcp.state.entries {
			if e.decision.Flow.ApplicationID == "" || (!b.transitionAll && !affected[e.decision.Flow.ApplicationID]) || e.mode == "closed" {
				continue
			}
			if e.openCancel != nil {
				e.openCancel()
			}
			if e.openDone != nil {
				pending = append(pending, e.openDone)
			}
			if e.local != nil {
				sockets = append(sockets, e.local)
			}
			if e.upstream != nil {
				sockets = append(sockets, e.upstream)
			}
			e.local = nil
			e.upstream = nil
			e.mode = "hot_attach"
			e.normalTeardown = true
			e.last = time.Now()
			e.localBuffer = LocalTCPBuffer{}
			b.evidence.RecordHotAttach(e.identity, e.tuple, epoch, "HOT_ATTACH_RETIRED", e.decision.Revision)
		}
		tcp.state.mu.Unlock()
	}
	b.mu.Lock()
	for tuple, f := range b.flows {
		if f.decision.Flow.ApplicationID == "" || (!b.transitionAll && !affected[f.decision.Flow.ApplicationID]) {
			continue
		}
		f.retired = true
		f.once.Do(func() { close(f.done) })
		if f.cancelOpen != nil {
			f.cancelOpen()
		}
		if f.datagram != nil {
			datagrams = append(datagrams, f.datagram)
		}
		if f.queue == nil {
			delete(b.flows, tuple)
		} else {
			for {
				select {
				case <-f.queue:
					b.Drops.Add(1)
					b.evidence.RecordDrop(f.identity, tuple, "HOT_ATTACH_UDP_RETIRED", false)
				default:
					goto drained
				}
			}
		}
	drained:
		b.evidence.RecordHotAttach(f.identity, tuple, epoch, "HOT_ATTACH_RETIRED", f.decision.Revision)
		b.hot.mu.Lock()
		b.hot.status.UDPRetired++
		b.hot.mu.Unlock()
	}
	b.mu.Unlock()
	b.policyMu.Unlock()
	// Phase 2: selected sockets abort. Other applications continue using capture.
	for _, c := range sockets {
		abortHotTCP(c)
	}
	for _, d := range datagrams {
		_ = d.Close()
	}
	for _, done := range pending {
		select {
		case <-done:
		case <-b.ctx.Done():
		}
	}

	// Phase 3 publishes policy atomically. Fresh SYNs cannot enter obsolete policy
	// while the application fence is up; the private cache epoch advances here.
	b.policyMu.Lock()
	if !preserveTCP {
		b.snapshotHotTargets()
	}
	err := change()
	b.policyEpoch.Add(1)
	b.transition = nil
	b.transitionAll = false
	if !preserveTCP {
		b.hot.mu.Lock()
		b.hot.status.State = "HOT_ATTACH_RECONNECTING"
		if err != nil {
			b.hot.targetError = "policy activation: " + err.Error()
		}
		b.hot.mu.Unlock()
	}
	b.policyMu.Unlock()
	if !preserveTCP {
		select {
		case b.hotRequests <- struct{}{}:
		default:
		}
	}
	return err
}

// Caller holds policyMu for reading or writing.
func (b *WinDivertBackend) hotFrozen(d Decision) bool {
	return d.Flow.ApplicationID != "" && (b.transitionAll || b.transition[d.Flow.ApplicationID])
}

func (b *WinDivertBackend) hotAttachWorker() {
	defer b.wg.Done()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-b.hotRequests:
			status := b.hot.snapshot()
			if status.State == "HOT_ATTACH_PREPARING" {
				continue
			}
			epoch := status.Epoch
			b.hot.mu.Lock()
			targets := append([]hotAttachTarget(nil), b.hot.targets...)
			targetError := b.hot.targetError
			b.hot.mu.Unlock()
			deadline := time.Now().Add(hotAttachWindow)
			lastErr := ""
			resetCount := 0
			for {
				if b.ctx.Err() != nil {
					return
				}
				if b.hot.snapshot().Epoch != epoch {
					break
				}
				rows, err := queryOwnedTCP()
				lastErr = ""
				pending, scanned := 0, 0
				if targetError != "" {
					err = errors.New(targetError)
				}
				if err == nil {
					currentRows := map[Tuple]ownedTCPRow{}
					for _, r := range rows {
						currentRows[r.Tuple] = r
					}
					for _, target := range targets {
						row, exists := currentRows[target.row.Tuple]
						if !exists || row.PID != target.identity.PID || !IsCurrent(target.identity) {
							continue
						}

						if b.ctx.Err() != nil {
							break
						}
						if time.Now().After(deadline) {
							lastErr = "HOT_ATTACH time bound"
							pending++
							break
						}
						if row.PID == 0 || row.PID == uint32(os.Getpid()) || (row.Tuple.Destination.Addr().IsLoopback() || row.Tuple.Source.Addr() == row.Tuple.Destination.Addr()) {
							continue
						}
						considered, waiting, reset, resetErr := b.reconcileHotTarget(target, row, epoch)
						if considered {
							scanned++
						}
						if waiting {
							pending++
						}
						if reset {
							resetCount++
						}
						if resetErr != nil {
							lastErr = resetErr.Error()
						}
					}
				} else {
					lastErr = err.Error()
					pending++
				}
				b.hot.mu.Lock()
				if b.hot.status.Epoch == epoch {
					b.hot.status.Scanned = scanned
					b.hot.status.TCPReset = resetCount
					b.hot.status.Pending = pending
					b.hot.status.Error = lastErr
				}
				b.hot.mu.Unlock()
				if pending == 0 || time.Now().After(deadline) {
					b.hot.mu.Lock()
					if b.hot.status.Epoch == epoch {
						b.hot.status.CompletedAt = time.Now()
						b.hot.status.State = "HOT_ATTACH_NETWORK_READY"
						if pending != 0 || lastErr != "" {
							b.hot.status.State = "HOT_ATTACH_INCOMPLETE"
						}
					}
					b.hot.mu.Unlock()
					break
				}
				timer := time.NewTimer(250 * time.Millisecond)
				select {
				case <-b.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}
}
func (b *WinDivertBackend) hotBlocked() {
	b.hot.mu.Lock()
	b.hot.status.BlockedPackets++
	b.hot.mu.Unlock()
}
func sameHotOwner(a, b ProcessIdentity) bool {
	return a.PID == b.PID && a.CreationTime == b.CreationTime && strings.EqualFold(a.Path, b.Path)
}

// One short policy lease per target; table enumeration and waits do not retain a
// global reader across the entire sweep when another profile wants to publish.
func (b *WinDivertBackend) reconcileHotTarget(target hotAttachTarget, row ownedTCPRow, epoch uint64) (considered, waiting, reset bool, err error) {
	b.policyMu.RLock()
	defer b.policyMu.RUnlock()
	state := b.hot.snapshot()
	if state.Epoch != epoch || state.State == "HOT_ATTACH_PREPARING" || b.ctx.Err() != nil {
		return
	}
	id := target.identity
	d := b.classify(id, row.Tuple)
	tcp := b.tcp
	tcp.state.mu.Lock()
	entry := tcp.state.entries[row.Tuple]
	current := freshHotTCP(entry, id, d)
	retiring := entry != nil && sameHotOwner(entry.identity, id) && entry.mode == "hot_attach"
	tcp.state.mu.Unlock()
	if !needsHotAttach(d) && !retiring {
		return
	}
	considered = true
	if current {
		return
	}
	waiting = true
	err = resetOwnedTCP(row, id)
	if err == nil {
		reset = true
		b.evidence.RecordHotReset(id, row.Tuple, epoch, d)
	}
	return
}
