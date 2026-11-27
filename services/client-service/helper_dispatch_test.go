package clientservice

import (
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestHelperDispatchReadsCurrentProfileAfterReplacementDeletionAndTrial(t *testing.T) {
	p := profiles.Profile{ID: "!v2-helper", Name: "ChatGPT", Mode: profiles.Manual, RelayID: "VPS-01", Custom: true, Executables: []string{`C:\Apps\ChatGPT.exe`}}
	prepareAuto(&p)
	p.Identity = profiles.IdentityFor(p.Executables[0], "openai")
	c := policyController(t, p)
	root := wp.ProcessIdentity{PID: 1, CreationTime: 10, Path: p.Executables[0]}
	child := wp.ProcessIdentity{PID: 2, CreationTime: 20, ParentPID: 1, ParentCreationTime: 10, Path: `C:\Apps\Helper\codex.exe`}
	c.discovery = &groupDiscovery{all: []wp.ProcessIdentity{root, child}}
	if d := c.Classify(child, policyTuple("tcp", 443)); d.Route.RelayID != "VPS-01" || d.Group != p.ID {
		t.Fatal("verified helper not grouped", d)
	}
	p.Mode = profiles.Direct
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(child, policyTuple("tcp", 443)); !d.Route.Direct() || d.Group != p.ID {
		t.Fatal("binding cached previous route", d)
	}
	p.Mode = profiles.Manual
	p.Trial = &profiles.TrialScope{PID: 99, CreationTime: 100, Expires: time.Now().Add(time.Minute)}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(child, policyTuple("tcp", 443)); d.Group == p.ID {
		t.Fatal("old binding borrowed another trial", d)
	}
	c.Profiles.Delete(p.ID)
	if d := c.Classify(child, policyTuple("tcp", 443)); d.Group == p.ID {
		t.Fatal("deleted group retained authorization", d)
	}
	reused := child
	reused.CreationTime++
	if d := c.Classify(reused, policyTuple("tcp", 443)); d.Group == p.ID {
		t.Fatal("PID reuse retained helper group")
	}
}
