package windowsplatform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/buzzmean/neexitlag/core/gameudp"
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

func TestApexDiscoveryFindsDX12AndRetainsLegacySupport(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "steamapps", "common", "Apex Legends")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	preset := gameudp.Preset{ID: "apex", SteamID: "1172470"}
	dx12 := filepath.Join(dir, "r5apex_dx12.exe")
	legacy := filepath.Join(dir, "r5apex.exe")
	if err := os.WriteFile(dx12, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got := FindSteamGame([]string{root}, preset); got.Path != "" {
		t.Fatal("unverified Apex install trusted", got)
	}
	manifest := filepath.Join(root, "steamapps", "appmanifest_1172470.acf")
	if err := os.WriteFile(manifest, []byte(`"appid" "1172470" "installdir" "Apex Legends"`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := FindSteamGame([]string{root}, preset); got.Path != dx12 {
		t.Fatal("DX12 executable not discovered", got)
	}
	if err := os.WriteFile(legacy, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got := FindSteamGame([]string{root}, preset); got.Path != dx12 {
		t.Fatal("DX12 executable should be preferred when both exist", got)
	}
	if err := os.Remove(dx12); err != nil {
		t.Fatal(err)
	}
	if got := FindSteamGame([]string{root}, preset); got.Path != legacy {
		t.Fatal("legacy Apex executable not discovered", got)
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
