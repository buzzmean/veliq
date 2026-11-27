package clientservice

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func benchmarkClassifyController(b *testing.B, extra int) *Controller {
	b.Helper()
	c := New(context.Background())
	b.Cleanup(c.Close)
	c.enabled = true
	for n := 0; n < extra; n++ {
		p := profiles.Profile{ID: fmt.Sprintf("bench-%03d", n), Name: fmt.Sprintf("Application %d", n), Executables: []string{fmt.Sprintf(`C:\Bench\app-%03d.exe`, n)}, Mode: profiles.Auto, Custom: true}
		if err := c.Profiles.Upsert(p); err != nil {
			b.Fatal(err)
		}
	}
	return c
}

func BenchmarkApplicationDispatch(b *testing.B) {
	for _, extra := range []int{6, 57} {
		for _, kind := range []string{"registry_miss", "group_miss", "classify_udp_direct", "classify_tcp_auto"} {
			b.Run(fmt.Sprintf("profiles=%d/%s", len(profiles.Defaults())+extra, kind), func(b *testing.B) {
				c := benchmarkClassifyController(b, extra)
				id := wp.ProcessIdentity{PID: 16036, CreationTime: 134402359570643174, Path: `C:\Games\Warhammer\warhammer 40000 space marine 2 - retail.exe`}
				tuple := policyTuple("udp", 27015)
				if kind == "classify_tcp_auto" {
					tuple = policyTuple("tcp", 443)
				}
				b.ReportAllocs()
				b.ResetTimer()
				var decision wp.Decision
				var profile profiles.Profile
				for n := 0; n < b.N; n++ {
					switch kind {
					case "registry_miss":
						profile, _ = c.Profiles.Match(id)
					case "group_miss":
						profile, _ = c.matchEligibleApplication(id)
					default:
						decision = c.Classify(id, tuple)
					}
				}
				runtime.KeepAlive(decision)
				runtime.KeepAlive(profile)
			})
		}
	}
}

func BenchmarkApplicationDispatchParallel(b *testing.B) {
	c := benchmarkClassifyController(b, 6)
	id := wp.ProcessIdentity{PID: 16036, CreationTime: 134402359570643174, Path: `C:\Games\Warhammer\warhammer 40000 space marine 2 - retail.exe`}
	tuple := policyTuple("udp", 27015)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var d wp.Decision
		for pb.Next() {
			d = c.Classify(id, tuple)
		}
		runtime.KeepAlive(d)
	})
}
