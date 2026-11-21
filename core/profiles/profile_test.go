package profiles

import (
	"testing"
)

func TestIdentityAndModes(t *testing.T) {
	p := Profile{ID: "custom", Name: "Game", Executables: []string{`C:\Games\cs2.exe`}, Mode: Auto, Custom: true}
	i := Identity{PID: 12, Path: `c:\games\CS2.exe`, CreationTime: 123}
	if !p.Matches(i) {
		t.Fatal("path match")
	}
	i.Path = `C:\Other\cs2.exe`
	if p.Matches(i) {
		t.Fatal("matched wrong executable path")
	}
	i.CreationTime = 0
	if p.Matches(i) {
		t.Fatal("unidentified process")
	}
	p.Mode = Manual
	if p.Validate() == nil {
		t.Fatal("manual without relay")
	}
	for _, p := range Defaults() {
		if e := p.Validate(); e != nil {
			t.Fatal(e)
		}
	}
}
