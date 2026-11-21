package flowpolicy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var dtKey = DirectTimeoutKey{Network: "net-a", Application: "chrome", Host: "claude.ai", Port: 443}

func TestTwoTimeoutsWithinWindowActivateOneDoesNot(t *testing.T) {
	c := NewDirectTimeoutCache()
	t0 := time.Now()
	if c.RecordTimeout(dtKey, t0) {
		t.Fatal("a single timeout must not be cached")
	}
	if active, _ := c.Lookup(dtKey, t0); active {
		t.Fatal("single timeout steered traffic to the relay")
	}
	if !c.RecordTimeout(dtKey, t0.Add(59*time.Second)) {
		t.Fatal("second timeout within 60 s must activate")
	}
	if active, due := c.Lookup(dtKey, t0.Add(60*time.Second)); !active || due {
		t.Fatalf("active=%v due=%v", active, due)
	}
}

func TestTimeoutsFurtherApartThanWindowRestartTheCount(t *testing.T) {
	c := NewDirectTimeoutCache()
	t0 := time.Now()
	c.RecordTimeout(dtKey, t0)
	if c.RecordTimeout(dtKey, t0.Add(61*time.Second)) {
		t.Fatal("timeouts 61 s apart must not count as consecutive")
	}
	if !c.RecordTimeout(dtKey, t0.Add(62*time.Second)) {
		t.Fatal("the restarted count must still reach two")
	}
}

func TestSuccessBetweenTimeoutsResetsAndRecoversActiveOrigin(t *testing.T) {
	c := NewDirectTimeoutCache()
	t0 := time.Now()
	c.RecordTimeout(dtKey, t0)
	c.RecordSuccess(dtKey)
	if c.RecordTimeout(dtKey, t0.Add(time.Second)) {
		t.Fatal("success must reset the consecutive count")
	}
	c.RecordTimeout(dtKey, t0.Add(2*time.Second)) // active now
	c.RecordSuccess(dtKey)
	if active, _ := c.Lookup(dtKey, t0.Add(3*time.Second)); active {
		t.Fatal("a successful DIRECT open must return the origin to DIRECT")
	}
	if s := c.Stats(); s.RecoveredDirect != 1 || s.ActiveOrigins != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestBackgroundProbeOncePerTTLAndRenewalOnTimeout(t *testing.T) {
	c := NewDirectTimeoutCache()
	t0 := time.Now()
	c.RecordTimeout(dtKey, t0)
	c.RecordTimeout(dtKey, t0.Add(time.Second))
	if _, due := c.Lookup(dtKey, t0.Add(9*time.Minute)); due {
		t.Fatal("probe due before the TTL elapsed")
	}
	at := t0.Add(time.Second + DirectTimeoutTTL)
	if active, due := c.Lookup(dtKey, at); !active || !due {
		t.Fatalf("active=%v due=%v", active, due)
	}
	// Traffic keeps going to the relay while the probe runs, but only one probe starts.
	if active, due := c.Lookup(dtKey, at.Add(time.Second)); !active || due {
		t.Fatalf("second caller claimed the probe: active=%v due=%v", active, due)
	}
	// The probe timed out again: the entry is renewed for another TTL.
	c.RecordTimeout(dtKey, at.Add(2*time.Second))
	c.ProbeDone(dtKey, at.Add(2*time.Second), true)
	if _, due := c.Lookup(dtKey, at.Add(5*time.Minute)); due {
		t.Fatal("renewed entry probed again too early")
	}
	if _, due := c.Lookup(dtKey, at.Add(2*time.Second+DirectTimeoutTTL)); !due {
		t.Fatal("renewed entry never probed again")
	}
}

func TestInconclusiveProbeRetriesSoon(t *testing.T) {
	c := NewDirectTimeoutCache()
	t0 := time.Now()
	c.RecordTimeout(dtKey, t0)
	c.RecordTimeout(dtKey, t0)
	at := t0.Add(DirectTimeoutTTL)
	if _, due := c.Lookup(dtKey, at); !due {
		t.Fatal("probe not due")
	}
	c.ProbeDone(dtKey, at, false)
	if _, due := c.Lookup(dtKey, at.Add(30*time.Second)); due {
		t.Fatal("retry before the short backoff")
	}
	if _, due := c.Lookup(dtKey, at.Add(61*time.Second)); !due {
		t.Fatal("inconclusive probe was not retried")
	}
}

func TestKeysAreIsolatedAndHitsCounted(t *testing.T) {
	c := NewDirectTimeoutCache()
	t0 := time.Now()
	other := dtKey
	other.Network = "net-b"
	c.RecordTimeout(dtKey, t0)
	c.RecordTimeout(dtKey, t0)
	if active, _ := c.Lookup(other, t0); active {
		t.Fatal("another network inherited the cache")
	}
	for i := 0; i < 5; i++ {
		c.Lookup(dtKey, t0)
	}
	s := c.Stats()
	if s.Hits != 5 || s.ActiveOrigins != 1 || len(s.Top) != 1 || s.Top[0].Host != "claude.ai" || s.Top[0].Hits != 5 || s.Created != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestCapacityIsBoundedAndConcurrencySafe(t *testing.T) {
	c := NewDirectTimeoutCache()
	t0 := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := DirectTimeoutKey{Network: "n", Application: "a", Host: fmt.Sprintf("h%d-%d.example", g, i), Port: 443}
				c.RecordTimeout(k, t0)
				c.RecordTimeout(k, t0)
				c.Lookup(k, t0)
				c.Stats()
			}
		}(g)
	}
	wg.Wait()
	if n := len(c.entries); n > directTimeoutCap {
		t.Fatalf("cache grew to %d entries", n)
	}
}

func TestAddressVerdictRequiresDistinctIPsForDomainAndKeepsNetworkProfileIsolation(t *testing.T) {
	c := NewDirectTimeoutCache()
	now := time.Now()
	a := dtKey
	a.Address = "142.251.150.4"
	b := a
	b.Address = "142.251.151.4"
	for i := 0; i < 10; i++ {
		c.RecordTimeout(a, now)
	}
	if active, _ := c.Lookup(dtKey, now); active {
		t.Fatal("same IP burst poisoned domain")
	}
	if !c.AddressFailed(a, now) || c.AddressFailed(b, now) {
		t.Fatal("address not isolated")
	}
	c.RecordTimeout(b, now.Add(time.Second))
	if active, _ := c.Lookup(dtKey, now); !active {
		t.Fatal("two failed IPs did not make domain relay-first")
	}
	for _, other := range []DirectTimeoutKey{{Network: "other", Application: dtKey.Application, Host: dtKey.Host, Port: 443}, {Network: dtKey.Network, Application: "edge", Host: dtKey.Host, Port: 443}, {Network: dtKey.Network, Application: dtKey.Application, Host: dtKey.Host, Port: 8443}} {
		if active, _ := c.Lookup(other, now); active {
			t.Fatal("verdict leaked", other)
		}
	}
	if _, due := c.Lookup(dtKey, now.Add(DirectTimeoutTTL+time.Second)); !due {
		t.Fatal("bounded background recheck never due")
	}
	c.RecordSuccess(b)
	if active, _ := c.Lookup(dtKey, now); active {
		t.Fatal("verified address recovery did not clear domain")
	}
	if !c.AddressFailed(a, now) {
		t.Fatal("recovery of peer erased failed IP")
	}
}
