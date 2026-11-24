package windowsplatform

import (
	"errors"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type PUBGInstallation struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

var steamLibraryPath = regexp.MustCompile(`"path"\s*"((?:\\.|[^"\\])*)"`)
var steamAppID = regexp.MustCompile(`"appid"\s*"([0-9]+)"`)
var steamInstallDir = regexp.MustCompile(`"installdir"\s*"([^"\\/]+)"`)

// FindPUBG reads Steam's bounded text manifests and file metadata only. It never
// opens the game's executable content, changes Steam files or touches memory.
func FindPUBG(roots []string) PUBGInstallation { return FindSteamGame(roots, gameudp.Presets()[0]) }

func FindSteamGame(roots []string, preset gameudp.Preset) PUBGInstallation {
	valid := false
	for _, p := range gameudp.Presets() {
		if p.ID == preset.ID && p.SteamID == preset.SteamID {
			preset = p
			valid = true
			break
		}
	}
	if !valid {
		return PUBGInstallation{Reason: "UNKNOWN_GAME_PRESET"}
	}
	libraries := []string{}
	seen := map[string]bool{}
	add := func(p string) {
		if len(libraries) < 32 && filepath.IsAbs(p) && len(p) <= 2048 && !strings.HasPrefix(p, `\\`) && !seen[strings.ToLower(p)] {
			seen[strings.ToLower(p)] = true
			libraries = append(libraries, p)
		}
	}
	for _, root := range roots {
		add(root)
		p := filepath.Join(root, "steamapps", "libraryfolders.vdf")
		if data, err := readSteamText(p); err == nil {
			for _, m := range steamLibraryPath.FindAllSubmatch(data, 32) {
				v := strings.ReplaceAll(string(m[1]), `\\`, `\`)
				add(v)
			}
		}
	}
	for _, library := range libraries {
		data, err := readSteamText(filepath.Join(library, "steamapps", "appmanifest_"+preset.SteamID+".acf"))
		if err != nil {
			continue
		}
		appid := steamAppID.FindSubmatch(data)
		if len(appid) != 2 || string(appid[1]) != preset.SteamID {
			continue
		}
		match := steamInstallDir.FindSubmatch(data)
		if len(match) != 2 {
			continue
		}
		name := string(match[1])
		if name == "." || name == ".." || strings.ContainsAny(name, ":\x00\r\n") {
			continue
		}
		parts := append([]string{library, "steamapps", "common", name}, preset.Relative...)
		path := filepath.Join(parts...)
		if preset.ID == "apex" {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				path = filepath.Join(filepath.Dir(path), "r5apex.exe")
			}
		}
		file, err := os.Lstat(path)
		if err == nil && file.Mode().IsRegular() && file.Mode()&os.ModeSymlink == 0 {
			return PUBGInstallation{Path: path, Reason: "STEAM_APP_" + preset.SteamID + "_VERIFIED_PATH"}
		}
	}
	return PUBGInstallation{Reason: "GAME_NOT_INSTALLED"}
}
func readSteamText(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() > 256*1024 {
		return nil, errors.New("STEAM_MANIFEST_INVALID")
	}
	data := make([]byte, s.Size())
	n, err := f.ReadAt(data, 0)
	if err != nil || n != len(data) {
		return nil, errors.New("STEAM_MANIFEST_READ_FAILED")
	}
	return data, nil
}
