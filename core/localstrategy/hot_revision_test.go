package localstrategy

import "testing"

func TestHotAttachRevisionIsScopedContentNotReloadEpoch(t *testing.T) {
	e := New()
	a := []string{`C:\Apps\chrome.exe`}
	b := []string{`C:\Apps\Discord.exe`}
	c := Config{Version: 1, Enabled: true, User: []Profile{{ID: "chrome", Name: "Chrome", Version: 1, Application: a[0], Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.0/24"}, Cutoff: 2, Strategy: "tcp-split-1", Enabled: true}}}
	if err := e.Reload(c); err != nil {
		t.Fatal(err)
	}
	original := e.ApplicationRevision(a)
	if original == "" || e.ApplicationRevision(b) != "" {
		t.Fatal("unrelated app revision")
	}
	c.User = append(c.User, Profile{ID: "discord", Name: "Discord", Version: 1, Application: b[0], Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.0/24"}, Cutoff: 2, Strategy: "tcp-split-1", Enabled: true})
	if err := e.Reload(c); err != nil {
		t.Fatal(err)
	}
	if e.ApplicationRevision(a) != original {
		t.Fatal("Discord change invalidated Chrome")
	}
	c.User[0].Cutoff = 3
	if err := e.Reload(c); err != nil {
		t.Fatal(err)
	}
	updated := e.ApplicationRevision(a)
	if updated == original {
		t.Fatal("real change not versioned")
	}
	fresh := New()
	if err := fresh.Reload(c); err != nil {
		t.Fatal(err)
	}
	if fresh.ApplicationRevision(a) != updated {
		t.Fatal("revision used reload epoch instead of content")
	}
}
