package transport

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestFleetBudgetHotEnablePreservesExistingReservations(t *testing.T) {
	budget := &FleetBudget{}
	var live []func()
	for i := 0; i < FleetSessionLimit+2; i++ {
		release, ok := budget.reserve(fleetSession)
		if !ok {
			t.Fatal("feature-off budget denied a session")
		}
		live = append(live, release)
	}
	budget.SetEnabled(true)
	if s := budget.Snapshot(); s.Sessions != FleetSessionLimit+2 || !s.Enabled {
		t.Fatalf("lost existing sessions: %+v", s)
	}
	if _, ok := budget.reserve(fleetSession); ok {
		t.Fatal("over-limit session admitted after opt-in")
	}
	for _, release := range live[:FleetSessionLimit+1] {
		release()
		release()
	}
	release, ok := budget.reserve(fleetSession)
	if !ok {
		t.Fatal("released capacity not reusable")
	}
	release()
	live[FleetSessionLimit+1]()
	if sessions := budget.Snapshot().Sessions; sessions != 0 {
		t.Fatalf("session permits leaked: %d", sessions)
	}
}

func TestFleetBudgetConcurrentReservations(t *testing.T) {
	for _, requests := range []int{10, 40, 120} {
		t.Run(fmt.Sprint(requests), func(t *testing.T) {
			budget := &FleetBudget{}
			budget.SetEnabled(true)
			var work sync.WaitGroup
			type reservation struct {
				resource fleetResource
				release  func()
			}
			held := make(chan reservation, requests*int(fleetResources))
			for i := 0; i < requests; i++ {
				work.Add(1)
				go func() {
					defer work.Done()
					for resource := fleetResource(0); resource < fleetResources; resource++ {
						if release, ok := budget.reserve(resource); ok {
							held <- reservation{resource, release}
						}
					}
				}()
			}
			work.Wait()
			close(held)
			want := FleetOccupancy{true, FleetSessionLimit, min(requests, FleetApplicationLimit), FleetProbeLimit, min(requests, FleetWaitingLimit)}
			if got := budget.Snapshot(); got != want {
				t.Fatalf("occupancy = %+v, want %+v", got, want)
			}
			for entry := range held {
				entry.release()
			}
			if got := budget.Snapshot(); got != (FleetOccupancy{Enabled: true}) {
				t.Fatalf("permits leaked: %+v", got)
			}
		})
	}
}

func TestFleetEchoLimitRollingWindow(t *testing.T) {
	budget := &FleetBudget{}
	now := time.Unix(100, 0)
	for i := 0; i < FleetEchoLimit; i++ {
		if !budget.allowEcho(now) {
			t.Fatal("disabled budget throttled traffic")
		}
	}
	budget.SetEnabled(true)
	if budget.allowEcho(now.Add(FleetEchoWindow - time.Millisecond)) {
		t.Fatal("hot opt-in discarded the rolling history")
	}
	if !budget.allowEcho(now.Add(FleetEchoWindow)) {
		t.Fatal("window did not free an old permit")
	}
}
