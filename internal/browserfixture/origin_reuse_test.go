package browserfixture

import (
	"os"
	"testing"
)

func TestChromiumOriginReuseBaseline(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_ORIGIN_REUSE") != "1" {
		t.Skip("explicit isolated trust/browser fixture")
	}
	chrome := ChromePath()
	if chrome == "" {
		t.Fatal("actual Chromium required")
	}
	f := NewOriginReuse(t)
	f.Run(t, chrome, "127.0.0.1", ReuseLocalHost, []string{"--no-proxy-server"})
	requests := f.Requests(t)
	for _, r := range requests {
		t.Logf("ORIGIN_REUSE_BASELINE %+v", r)
		if r.Connection != requests[0].Connection || r.SNI != ReuseLocalHost || r.Source != "127.0.0.1" {
			t.Fatal("coalescing not exercised; no isolation conclusion possible")
		}
	}
	t.Log("COALESCING_PRECONDITION_OBSERVED: different policy authorities share one verified H2 connection")
}
