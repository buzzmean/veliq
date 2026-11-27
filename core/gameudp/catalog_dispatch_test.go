package gameudp

import (
	"strings"
	"testing"
)

func TestKnownExecutablePreservesCatalogAndIndependentDiscoveryData(t *testing.T) {
	first := Presets()
	for _, p := range first {
		if !IsKnownExecutable(p.Executable) || !IsKnownExecutable(strings.ToUpper(p.Executable)) {
			t.Fatal("catalog executable omitted", p.Executable)
		}
	}
	for _, unknown := range []string{"", "ordinary.exe", `C:\Game\cs2.exe`, "cs2.exe.bak", "warhammer 40000 space marine 2 - retail.exe"} {
		if IsKnownExecutable(unknown) {
			t.Fatal("unknown/path became known executable", unknown)
		}
	}
	first[0].Executable = "foreign.exe"
	first[0].Relative[0] = "changed"
	second := Presets()
	if second[0].Executable != "TslGame.exe" || second[0].Relative[0] != "TslGame" || IsKnownExecutable("foreign.exe") {
		t.Fatal("discovery caller modified shared catalog")
	}
}
