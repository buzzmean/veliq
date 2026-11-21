package browserproxy

import "testing"

func TestOnlyCompleteClientHelloMayReplayNeverEarlyDataOrApplicationRequests(t *testing.T) {
	ch := []byte{22, 3, 1, 0, 7, 1, 0, 0, 3, 1, 2, 3}
	if !clientHelloFlight(ch) {
		t.Fatal("complete ClientHello rejected")
	}
	for _, raw := range [][]byte{ch[:10], []byte("GET / HTTP/1.1"), append(append([]byte{}, ch...), 23, 3, 3, 0, 1, 42), {22, 3, 3, 0, 4, 2, 0, 0, 0}} {
		if clientHelloFlight(raw) {
			t.Fatal("unsafe first flight accepted")
		}
	}
}
