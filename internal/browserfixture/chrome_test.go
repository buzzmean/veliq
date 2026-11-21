package browserfixture

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCDPPageReadinessWaitsForActualTarget(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(503)
		case 2:
			fmt.Fprint(w, "[]")
		default:
			fmt.Fprint(w, `[{"type":"page","webSocketDebuggerUrl":"ws://127.0.0.1:1/test"}]`)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	page, e := waitCDPPage(ctx, server.Client(), server.URL)
	if e != nil || page != "ws://127.0.0.1:1/test" || calls.Load() != 3 {
		t.Fatal(page, e, calls.Load())
	}
}
