//go:build windows

package windowsplatform

import (
	"encoding/binary"
	"testing"
)

// WinDivert 2.2.2 WINDIVERT_DATA_FLOW uses host-order UINT32 words in
// least-significant-first order. IPv4 occupies word 0, followed by 0xffff.
// The addresses below match gamePacket, independently of the production reader.
func nativeGameFlowAddress(pid uint32, endpoint uint64) [80]byte {
	var a [80]byte
	a[8], a[9], a[10] = 2, 1, 2 // FLOW_ESTABLISHED, outbound IPv4
	d := a[16:]
	binary.LittleEndian.PutUint64(d[0:8], endpoint)
	binary.LittleEndian.PutUint32(d[16:20], pid)
	copy(d[20:36], []byte{1, 2, 0, 192, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	copy(d[36:52], []byte{1, 46, 157, 18, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.LittleEndian.PutUint16(d[52:54], 50000)
	binary.LittleEndian.PutUint16(d[54:56], 7766)
	d[56] = 17
	return a
}

func TestNativeFlowIPv4IdentityAndLifetime(t *testing.T) {
	id := nativeGameIdentity(t)
	b, _ := captureFixture(t)
	_, tuple := gamePacket()
	a := nativeGameFlowAddress(id.PID, 0x1122334455667788)
	b.trackFlow(a)
	association, ok := b.associations.Get(tuple, id)
	if !ok || association.Endpoint != 0x1122334455667788 {
		t.Fatalf("native FLOW does not match packet tuple: %+v, found=%v", association, ok)
	}
	reused := id
	reused.CreationTime++
	if b.associations.MarkGameFirstFlight(tuple, reused) {
		t.Fatal("reused PID inherited native proof")
	}
	if !b.associations.MarkGameFirstFlight(tuple, id) {
		t.Fatal("fresh native FLOW lost first-flight proof")
	}
	b.trackFlow(a)
	if b.associations.MarkGameFirstFlight(tuple, id) {
		t.Fatal("duplicate FLOW rearmed consumed proof")
	}
	stale := nativeGameFlowAddress(id.PID, 7)
	stale[9] = 2
	b.trackFlow(stale)
	if _, ok := b.associations.Get(tuple, id); !ok {
		t.Fatal("stale FLOW_DELETED removed a different endpoint")
	}
	a[9] = 2
	b.trackFlow(a)
	if _, ok := b.associations.Get(tuple, id); ok {
		t.Fatal("matching FLOW_DELETED retained association")
	}
}

func TestNativeFlowIPv4LateEventDoesNotRearm(t *testing.T) {
	id := nativeGameIdentity(t)
	b, _ := captureFixture(t)
	_, tuple := gamePacket()
	// A packet/UDP-owner fallback was already observed before native FLOW.
	b.associations.Put(Association{Identity: id, Tuple: tuple})
	b.flows[tuple] = &captureFlow{identity: id, done: make(chan struct{})}
	b.trackFlow(nativeGameFlowAddress(id.PID, 9))
	association, ok := b.associations.Get(tuple, id)
	if !ok || association.Endpoint != 9 {
		t.Fatal("late native FLOW failed to update endpoint")
	}
	delete(b.flows, tuple) // expiry of the packet cache must not rearm proof
	if b.associations.MarkGameFirstFlight(tuple, id) {
		t.Fatal("late FLOW rearmed an already observed UDP flow")
	}
}
