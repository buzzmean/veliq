package profiles

import "testing"

func TestGroupAncestryAndPIDReuse(t *testing.T) {
	p := Profile{ID: "openai", Name: "ChatGPT", Executables: []string{`C:\Apps\ChatGPT.exe`}, Identity: IdentityFor(`C:\Apps\ChatGPT.exe`, "openai"), Mode: Auto}
	root := Identity{PID: 1, CreationTime: 10, Path: `C:\Apps\ChatGPT.exe`}
	child := Identity{PID: 2, CreationTime: 20, Path: `C:\Apps\codex-a8\codex.exe`, ParentPID: 1, ParentCreationTime: 10}
	if !p.GroupMatch(child, []Identity{root, child}) {
		t.Fatal("helper not inherited")
	}
	foreign := root
	foreign.Path = `C:\Other\Other.exe`
	child.Path = `C:\Other\codex.exe`
	if p.GroupMatch(child, []Identity{foreign, child}) {
		t.Fatal("foreign app inherited")
	}
	child.Path = `C:\Other\codex.exe`
	root.CreationTime = 15
	if p.GroupMatch(child, []Identity{root, child}) {
		t.Fatal("PID reuse accepted")
	}
	root.CreationTime = 10
	child.Path = `C:\Tools\msedgewebview2.exe`
	if p.GroupMatch(child, []Identity{root, child}) {
		t.Fatal("generic helper matched")
	}
}
func TestVersionedIdentityConfinedToInstall(t *testing.T) {
	a := IdentityFor(`C:\Users\u\Discord\app-1.0.9212\Discord.exe`, "discord")
	for _, s := range []string{`C:\Users\u\Discord\app-1.0.9262\Discord.exe`, `C:\Users\u\Discord\app-1.0.9212\Discord.exe`} {
		if !a.Matches(Identity{PID: 1, CreationTime: 1, Path: s}) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{`C:\Other\app-1.0.9262\Discord.exe`, `C:\Users\u\Discord\app-evil\Discord.exe`, `C:\Users\u\Discord\app-1.0.9262\Other.exe`} {
		if a.Matches(Identity{PID: 1, CreationTime: 1, Path: s}) {
			t.Fatal("untrusted install matched", s)
		}
	}
}
func TestMSIXFamilyUpdateAndPublisherIsolation(t *testing.T) {
	a := IdentityFor(`C:\Program Files\WindowsApps\OpenAI.ChatGPT_1.2.3.4_x64__publisherA\app\ChatGPT.exe`, "openai")
	id := Identity{PID: 1, CreationTime: 1, Path: `C:\Program Files\WindowsApps\OpenAI.ChatGPT_2.3.4.5_x64__publisherA\app\ChatGPT.exe`}
	if !a.Matches(id) {
		t.Fatal("package version broke identity", a)
	}
	id.Path = `C:\Program Files\WindowsApps\OpenAI.ChatGPT_2.3.4.5_x64__publisherB\app\ChatGPT.exe`
	if a.Matches(id) {
		t.Fatal("different package publisher borrowed app identity")
	}
}
