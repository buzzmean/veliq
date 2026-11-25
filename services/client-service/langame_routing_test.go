package clientservice

import (
	"context"
	"reflect"
	"testing"

	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestLanGameConnectionsStayOutsideRouteSelection(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.enabled = true
	service := wp.ProcessIdentity{PID: 123, CreationTime: 456, Path: `D:\Club\LanGameService.exe`}
	c.isLanGameProcess = func(id wp.ProcessIdentity) bool {
		return id.PID == service.PID && id.CreationTime == service.CreationTime && id.Path == service.Path
	}
	connections := []wp.Tuple{
		destTuple("tcp", "93.184.216.34", 80), destTuple("tcp", "93.184.216.34", 443),
		destTuple("udp", "93.184.216.34", 12345), destTuple("tcp", "2606:4700:4700::1111", 443),
	}
	check := func() {
		t.Helper()
		for _, tuple := range connections {
			if d := c.Classify(service, tuple); !reflect.DeepEqual(d, wp.Decision{}) {
				t.Fatalf("club service traffic entered VELIQ for %v: %+v", tuple, d)
			}
		}
		if p, ok := c.matchApplication(service); ok {
			t.Fatalf("registered profile selected for a club service: %s", p.ID)
		}
		if p, ok := c.automaticProfile(service); ok {
			t.Fatalf("automatic profile selected for a club service: %s", p.ID)
		}
	}
	check()
	for _, mode := range []profiles.Mode{profiles.Block, profiles.Manual, profiles.Auto} {
		p := profiles.Profile{ID: "old-selection", Name: "Old selection", Executables: []string{service.Path}, Mode: mode, RelayID: "VPS-01", Custom: true}
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
		check()
		other := service
		other.CreationTime++
		if d := c.Classify(other, connections[0]); d.Flow.ApplicationID != p.ID || (mode == profiles.Block && !d.Block) {
			t.Fatalf("unverified same-image process lost its %s policy: %+v", mode, d)
		}
	}
}

func TestPrivateClubConnectionsSurviveEvenAnExplicitBlock(t *testing.T) {
	id := wp.ProcessIdentity{PID: 125, CreationTime: 458, Path: `C:\Test\client.exe`}
	c := policyController(t, profiles.Profile{ID: "block", Name: "Block", Executables: []string{id.Path}, Mode: profiles.Block, Custom: true})
	for _, ip := range []string{"10.20.30.40", "172.21.1.2", "192.168.1.50", "fd01::20"} {
		for _, port := range []uint16{1883, 3260} {
			if d := c.Classify(id, destTuple("tcp", ip, port)); !reflect.DeepEqual(d, wp.Decision{}) {
				t.Fatalf("VELIQ selected a route for private infrastructure %s/%d: %+v", ip, port, d)
			}
		}
		if d := c.Classify(id, destTuple("tcp", ip, 1884)); !d.Block {
			t.Fatalf("block policy lost for neighbouring port at %s: %+v", ip, d)
		}
	}
	if d := c.Classify(id, destTuple("tcp", "93.184.216.34", 1883)); !d.Block {
		t.Fatalf("public MQTT inherited private broker exception: %+v", d)
	}
}
