package windowsplatform

import (
	"testing"
	"time"
)

func TestLanGameSCMInstanceAndInteractiveWorker(t *testing.T) {
	const image = `F:\Club\LanGame\LanGameService.exe`
	service := ProcessIdentity{PID: 200, CreationTime: 10, Path: image}
	worker := ProcessIdentity{PID: 204, CreationTime: 11, Path: image, ParentPID: 200, ParentCreationTime: 10}
	request := ProcessIdentity{PID: worker.PID, CreationTime: worker.CreationTime, Path: `f:\club\langame\LANGAMESERVICE.EXE`}
	if !lanGameOwnershipMatches(service, service, service) || !lanGameOwnershipMatches(request, worker, service) {
		t.Fatal("verified service or interactive worker lost its native path")
	}
	checks := []struct {
		name    string
		changed func(*ProcessIdentity)
	}{
		{"different image", func(p *ProcessIdentity) { p.Path = `C:\Users\Player\LanGameService.exe` }},
		{"unrelated parent", func(p *ProcessIdentity) { p.ParentPID++ }},
		{"recycled parent PID", func(p *ProcessIdentity) { p.ParentCreationTime++ }},
		{"unknown parent birth", func(p *ProcessIdentity) { p.ParentCreationTime = 0 }},
		{"stale requested PID", func(p *ProcessIdentity) { p.CreationTime++ }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			live := worker
			check.changed(&live)
			if lanGameOwnershipMatches(request, live, service) {
				t.Fatal("unverified worker received a bypass")
			}
		})
	}
	lookalike := worker
	lookalike.Path = `C:\Users\Player\LanGameService.exe`
	if lanGameOwnershipMatches(lookalike, lookalike, service) {
		t.Fatal("a different executable with the same name matched the SCM image")
	}
	if lanGameOwnershipMatches(service, service, ProcessIdentity{}) {
		t.Fatal("no running SCM process")
	}
}

func TestLanGameVerdictFollowsProcessLifetime(t *testing.T) {
	var c lanGameIdentityCache
	service := ProcessIdentity{PID: 200, CreationTime: 10, Path: `D:\Club\LanGameService.exe`}
	now := time.Unix(100, 0)
	calls := 0
	trusted := true
	resolve := func(ProcessIdentity) bool { calls++; return trusted }
	if !c.match(service, now, resolve) || !c.match(service, now.Add(time.Second), resolve) || calls != 1 {
		t.Fatal("cached service should avoid additional SCM access")
	}
	trusted = false
	service.CreationTime++
	if c.match(service, now.Add(time.Second), resolve) || calls != 2 {
		t.Fatal("reused PID inherited its previous bypass")
	}
	trusted = true
	if !c.match(service, now.Add(3*time.Second), resolve) || calls != 3 {
		t.Fatal("temporary missing SCM identity should be rechecked")
	}
	service.Path = `D:\Other\LanGameService.exe`
	trusted = false
	if c.match(service, now.Add(4*time.Second), resolve) || calls != 4 {
		t.Fatal("cached result accepted an unverified image")
	}
}

func TestLanGameRejectsUnidentifiedOwners(t *testing.T) {
	for _, id := range []ProcessIdentity{
		{PID: 10, CreationTime: 20, Path: `C:\Program Files\LanGame\launcher.exe`},
		{PID: 10, CreationTime: 20, Path: "LanGameService.exe"},
		{PID: 10, Path: `C:\Program Files\LanGame\LanGameService.exe`},
	} {
		if IsLanGameServiceProcess(id) {
			t.Fatalf("accepted incomplete or unrelated identity: %v", id)
		}
	}
}

func TestLanGameStartupBindsConfiguredImageAndVerifiedSCMParent(t *testing.T) {
	const image = `E:\Diskless Tools\Langame\LanGameService.exe`
	for _, command := range []string{
		image, `"` + image + `" -service`, image + " -service", `"e:\diskless tools\Langame\LanGameService.exe"`,
	} {
		if !lanGameConfiguredImage(command, image) {
			t.Errorf("rejected registered image: %q", command)
		}
	}
	for _, command := range []string{
		image + ".old", `"` + image + `".bak`, `C:\Temp\wrapper.exe "` + image + `"`,
		`"C:\Users\Player\LanGameService.exe"`, `"` + image, "",
	} {
		if lanGameConfiguredImage(command, image) {
			t.Errorf("accepted unregistered image: %q", command)
		}
	}
	const systemImage = `C:\Windows\System32\services.exe`
	manager := ProcessIdentity{PID: 40, CreationTime: 1, Path: systemImage}
	root := ProcessIdentity{PID: 80, CreationTime: 3, ParentPID: manager.PID, ParentCreationTime: manager.CreationTime, Path: image}
	if !lanGameManagerMatches(root, manager, systemImage, "S-1-5-18", 0) {
		t.Fatal("starting registered service lost its SCM provenance")
	}
	if lanGameManagerMatches(root, manager, systemImage, "S-1-5-18", 1) ||
		lanGameManagerMatches(root, manager, systemImage, "S-1-5-19", 0) {
		t.Fatal("interactive or non-System process impersonated SCM")
	}
	manager.Path = `C:\Temp\services.exe`
	if lanGameManagerMatches(root, manager, systemImage, "S-1-5-18", 0) {
		t.Fatal("manager path lookalike accepted")
	}
	manager.Path, manager.CreationTime = systemImage, manager.CreationTime+1
	if lanGameManagerMatches(root, manager, systemImage, "S-1-5-18", 0) {
		t.Fatal("recycled manager PID accepted")
	}
}
