//go:build windows

package windowsplatform

import (
	"os"
	"testing"
	"time"
)

func TestQUICOwnerSameHandleBirthImageAndSID(t *testing.T) {
	id := quicProbeOwner(t)
	sid, err := ProcessUserSID(id)
	if err != nil || !CurrentQUICProcessOwner(id, sid) {
		t.Fatal("current native owner not accepted", err)
	}
	changed := id
	changed.CreationTime++
	if CurrentQUICProcessOwner(changed, sid) {
		t.Fatal("PID reuse accepted")
	}
	changed = id
	changed.Path = `C:\Different\chrome.exe`
	if CurrentQUICProcessOwner(changed, sid) {
		t.Fatal("wrong image accepted")
	}
	for _, bad := range []string{"", "not-a-SID", "S-1-0-0"} {
		if CurrentQUICProcessOwner(id, bad) {
			t.Fatal("wrong SID accepted")
		}
	}
	ticks, freq := quicOwnerClock()
	if !quicFreshTicks(ticks, ticks, freq) {
		t.Fatal("native timestamp clock unavailable")
	}
	proc, err := os.FindProcess(int(id.PID))
	if err != nil {
		t.Fatal(err)
	}
	if err = proc.Kill(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for CurrentQUICProcessOwner(id, sid) {
		if time.Now().After(deadline) {
			t.Fatal("exited process accepted")
		}
		time.Sleep(time.Millisecond)
	}
	t.Log("same-handle owner/SID/birth/image verified; replacement and exit denied")
}
