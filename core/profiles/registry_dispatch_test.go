package profiles

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
)

func dispatchProfile(id string, custom bool) Profile {
	return Profile{ID: id, Name: id, Executables: []string{`C:\Apps\client.exe`}, Mode: Auto, Custom: custom}
}

func TestRegistryMatchingKeepsCustomPriorityLexicalTieAndUpdates(t *testing.T) {
	r := New([]Profile{dispatchProfile("a-built-in", false), dispatchProfile("z-custom", true), dispatchProfile("b-custom", true)})
	i := Identity{PID: 7, CreationTime: 10, Path: `c:\apps\CLIENT.exe`}
	assert := func(want string) {
		t.Helper()
		got, ok := r.Match(i)
		if !ok || got.ID != want {
			t.Fatalf("match %q/%t want %q", got.ID, ok, want)
		}
	}
	assert("b-custom")
	r.Delete("b-custom")
	assert("z-custom")
	changed := dispatchProfile("z-custom", false)
	if err := r.Upsert(changed); err != nil {
		t.Fatal(err)
	}
	assert("a-built-in")
	bad := dispatchProfile("0-invalid", true)
	bad.Mode = Manual
	if r.Upsert(bad) == nil {
		t.Fatal("invalid configuration accepted")
	}
	assert("a-built-in")
	r.Delete("a-built-in")
	assert("z-custom")
	r.Delete("missing")
	assert("z-custom")
}

func TestRegistryDispatchMatchesPreviousOrderingContract(t *testing.T) {
	all := Defaults()
	for n := 0; n < 30; n++ {
		p := dispatchProfile(fmt.Sprintf("custom-%02d", n), n%3 == 0)
		p.Executables = []string{fmt.Sprintf(`C:\Apps\app%d.exe`, n%4)}
		all = append(all, p)
	}
	r := New(all)
	for n := 0; n < 8; n++ {
		id := Identity{PID: 9, CreationTime: 11, Path: fmt.Sprintf(`C:\Apps\app%d.exe`, n)}
		legacy := r.List()
		sort.SliceStable(legacy, func(a, b int) bool { return legacy[a].Custom && !legacy[b].Custom })
		var want Profile
		matched := false
		for _, p := range legacy {
			if p.Matches(id) {
				want = p
				matched = true
				break
			}
		}
		got, ok := r.Match(id)
		if ok != matched || !reflect.DeepEqual(got, want) {
			t.Fatal("changed priority or profile", n, got, want)
		}
	}
}

func TestRegistryDispatchDoesNotAliasNestedProfileState(t *testing.T) {
	p := dispatchProfile("!v2-scope", true)
	p.Trial = &TrialScope{PID: 7, CreationTime: 10, Expires: time.Now().Add(time.Minute)}
	p.Identity = &ApplicationIdentity{Root: "c:/apps", Executable: "client.exe", Helpers: []string{"helper.exe"}}
	p.ProtocolHints = []string{"tcp"}
	p.PortHints = []uint16{443}
	p.Rules = []flowpolicy.Rule{{ID: "protected", Protocol: "tcp", Domains: []string{"chatgpt.com"}, CIDRs: []string{"192.0.2.0/24"}, Ports: []flowpolicy.PortRange{{First: 443, Last: 443}}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}
	p.BrowserRecoveryRules = append([]flowpolicy.Rule(nil), p.Rules...)
	r := New([]Profile{p})
	expected, _ := r.Get(p.ID)
	mutate := func(q *Profile) {
		q.Executables[0] = "other.exe"
		q.Identity.Helpers[0] = "foreign.exe"
		q.Trial.CreationTime++
		q.Rules[0].Domains[0] = "other.example"
		q.Rules[0].CIDRs[0] = "198.51.100.0/24"
		q.Rules[0].Ports[0].First = 80
		q.BrowserRecoveryRules[0].Domains[0] = "changed.example"
		q.ProtocolHints[0] = "udp"
		q.PortHints[0] = 80
	}
	mutate(&p)
	for _, kind := range []string{"match", "get", "list"} {
		var out Profile
		switch kind {
		case "match":
			var ok bool
			out, ok = r.Match(Identity{PID: 7, CreationTime: 10, Path: `C:\Apps\client.exe`})
			if !ok {
				t.Fatal("mutation affected registry")
			}
		case "get":
			out, _ = r.Get(expected.ID)
		case "list":
			out = r.List()[0]
		}
		if !reflect.DeepEqual(out, expected) {
			t.Fatal("incoming state alias", kind)
		}
		mutate(&out)
		after, _ := r.Get(expected.ID)
		if !reflect.DeepEqual(after, expected) {
			t.Fatal("returned state alias", kind)
		}
	}
	if _, ok := r.Match(Identity{PID: 7, CreationTime: 11, Path: `C:\Apps\client.exe`}); ok {
		t.Fatal("PID reuse borrowed trial")
	}
	expected.Trial.Expires = time.Now().Add(-time.Second)
	if err := r.Upsert(expected); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Match(Identity{PID: 7, CreationTime: 10, Path: `C:\Apps\client.exe`}); ok {
		t.Fatal("expired trial was cached")
	}
}

func TestRegistryDispatchConcurrentConfigurationRemainsAtomic(t *testing.T) {
	r := New([]Profile{dispatchProfile("base", false)})
	var wg sync.WaitGroup
	for worker := 0; worker < 5; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				if worker == 0 {
					p := dispatchProfile("custom", true)
					if err := r.Upsert(p); err != nil {
						t.Error(err)
					}
					r.Delete("custom")
					continue
				}
				p, ok := r.Match(Identity{PID: 1, CreationTime: 1, Path: `C:\Apps\client.exe`})
				if !ok || p.ID != "base" && p.ID != "custom" {
					t.Error("partial registry result", p.ID, ok)
				}
				_ = r.List()
				_, _ = r.Get("base")
				_ = r.MayMatchHelper(`C:\Apps\helper.exe`)
			}
		}(worker)
	}
	wg.Wait()
}

func TestRegistryHelperPredicateIsCandidateOnlyAndTracksChanges(t *testing.T) {
	p := dispatchProfile("owner", true)
	p.Identity = &ApplicationIdentity{Root: "c:/apps", Executable: "client.exe", Helpers: []string{"helper.exe"}}
	r := New([]Profile{p})
	if !r.MayMatchHelper(`C:\Unrelated\HELPER.exe`) {
		t.Fatal("helper candidate missing")
	}
	if _, ok := r.Match(Identity{PID: 9, CreationTime: 1, Path: `C:\Unrelated\HELPER.exe`}); ok {
		t.Fatal("candidate authorized without ancestry")
	}
	if r.MayMatchHelper(`C:\Apps\other.exe`) {
		t.Fatal("unlisted helper candidate")
	}
	p.Identity.Helpers = []string{"new.exe"}
	if err := r.Upsert(p); err != nil {
		t.Fatal(err)
	}
	if r.MayMatchHelper(`C:\Apps\helper.exe`) || !r.MayMatchHelper(`C:\Apps\NEW.exe`) {
		t.Fatal("stale helper configuration")
	}
	r.Delete(p.ID)
	if r.MayMatchHelper(`C:\Apps\new.exe`) {
		t.Fatal("deleted helper remained candidate")
	}
}
