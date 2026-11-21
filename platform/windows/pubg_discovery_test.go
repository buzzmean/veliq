package windowsplatform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPUBGDiscoveryRequiresSteamManifestAndExactExe(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "steamapps", "common", "PUBG", "TslGame", "Binaries", "Win64", "TslGame.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("fixture only"), 0600)
	if got := FindPUBG([]string{root}); got.Path != "" {
		t.Fatal("unverified basename trusted", got)
	}
	os.WriteFile(filepath.Join(root, "steamapps", "appmanifest_578080.acf"), []byte(`"AppState" { "appid" "578080" "installdir" "PUBG" }`), 0600)
	if got := FindPUBG([]string{root}); got.Path != path {
		t.Fatal(got)
	}
	os.WriteFile(filepath.Join(root, "steamapps", "appmanifest_578080.acf"), []byte(`"installdir" ".."`), 0600)
	if got := FindPUBG([]string{root}); got.Path != "" {
		t.Fatal("traversal trusted", got)
	}
}
func TestPUBGDiscoveryUsesAdditionalSteamLibrary(t *testing.T) {
	root := t.TempDir()
	library := t.TempDir()
	game := filepath.Join(library, "steamapps", "common", "PUBG", "TslGame", "Binaries", "Win64", "TslGame.exe")
	os.MkdirAll(filepath.Dir(game), 0700)
	os.WriteFile(game, []byte("fixture"), 0600)
	os.WriteFile(filepath.Join(library, "steamapps", "appmanifest_578080.acf"), []byte(`"appid" "578080" "installdir" "PUBG"`), 0600)
	os.MkdirAll(filepath.Join(root, "steamapps"), 0700)
	path := filepath.ToSlash(library)
	os.WriteFile(filepath.Join(root, "steamapps", "libraryfolders.vdf"), []byte(`"libraryfolders" { "1" { "path" "`+path+`" } }`), 0600)
	if got := FindPUBG([]string{root}); got.Path != game {
		t.Fatal(got)
	}
}

func TestSteamDiscoveryDoesNotTrustWrongAppID(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "steamapps", "common", "PUBG", "TslGame", "Binaries", "Win64", "TslGame.exe")
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte("fixture"), 0600)
	os.WriteFile(filepath.Join(root, "steamapps", "appmanifest_578080.acf"), []byte(`"appid" "730" "installdir" "PUBG"`), 0600)
	if got := FindPUBG([]string{root}); got.Path != "" {
		t.Fatal("wrong Steam app trusted", got)
	}
}
