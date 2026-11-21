package profiles

import (
	"errors"
	"path"
	"strings"
	"time"
)

// Anchor is selected by the user. Versioned matching is confined to the same
// install root and basename, never a global basename or an unverified publisher.
type ApplicationIdentity struct {
	PackageFamily string   `json:"package_family,omitempty"`
	RelativePath  string   `json:"relative_path,omitempty"`
	Root          string   `json:"root"`
	Executable    string   `json:"executable"`
	Versioned     bool     `json:"versioned,omitempty"`
	Helpers       []string `json:"helpers,omitempty"`
}

func (a ApplicationIdentity) Validate() error {
	if len(a.PackageFamily) > 256 || len(a.RelativePath) > 512 || strings.Contains(a.RelativePath, "..") {
		return errors.New("invalid package identity")
	}
	if a.Root == "" || len(a.Root) > 2048 || strings.ContainsAny(a.Root, "*\r\n") || len(a.Helpers) > 8 || !strings.HasSuffix(strings.ToLower(a.Executable), ".exe") {
		return errors.New("invalid application identity")
	}
	return nil
}
func versionDir(s string) bool {
	if !strings.HasPrefix(s, "app-") {
		return false
	}
	v := strings.TrimPrefix(s, "app-")
	if v == "" {
		return false
	}
	for _, c := range v {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func (a ApplicationIdentity) Matches(i Identity) bool {
	if i.PID == 0 || i.CreationTime == 0 {
		return false
	}
	p := normalize(i.Path)
	root := strings.TrimSuffix(normalize(a.Root), "/")
	if path.Base(p) != strings.ToLower(a.Executable) {
		return false
	}
	if a.PackageFamily != "" {
		prefix := root + "/"
		if !strings.HasPrefix(p, prefix) {
			return false
		}
		relative := strings.TrimPrefix(p, prefix)
		slash := strings.IndexByte(relative, '/')
		if slash < 0 {
			return false
		}
		family, ok := packageFamily(relative[:slash])
		return ok && family == a.PackageFamily && relative[slash+1:] == a.RelativePath
	}
	dir := path.Dir(p)
	return dir == root || a.Versioned && path.Dir(dir) == root && versionDir(path.Base(dir))
}
func IdentityFor(exe string, preset string) *ApplicationIdentity {
	p := normalize(exe)
	root := path.Dir(p)
	a := &ApplicationIdentity{Root: root, Executable: path.Base(p)}
	if preset == "discord" {
		a.Helpers = []string{"update.exe"}
	}
	if preset == "discord" && versionDir(path.Base(root)) {
		a.Root = path.Dir(root)
		a.Versioned = true
	}
	if preset == "openai" {
		if at := strings.Index(p, "/windowsapps/"); at >= 0 {
			base := p[:at+len("/windowsapps")]
			relative := p[at+len("/windowsapps/"):]
			if slash := strings.IndexByte(relative, '/'); slash > 0 {
				if family, ok := packageFamily(relative[:slash]); ok {
					a.Root = base
					a.PackageFamily = family
					a.RelativePath = relative[slash+1:]
				}
			}
		}
	}
	if preset == "openai" {
		a.Helpers = []string{"codex.exe", "codex-windows-sandbox-service.exe", "codex-computer-use-swift.exe"}
	}
	return a
}

// GroupMatch requires an exact parent birth identity at every hop. A reused PID,
// missing/exited parent, cycle or unapproved helper can never inherit policy.
func (p Profile) GroupMatch(child Identity, all []Identity) bool {
	if p.Trial != nil && !time.Now().Before(p.Trial.Expires) {
		return false
	}
	if p.Identity == nil || len(p.Identity.Helpers) == 0 || child.PID == 0 || child.CreationTime == 0 {
		return false
	}
	allowed := false
	for _, h := range p.Identity.Helpers {
		allowed = allowed || path.Base(normalize(child.Path)) == strings.ToLower(h)
	}
	if !allowed {
		return false
	}
	if p.Trial == nil && p.Identity.HelperInInstall(child) {
		return true
	}
	byPID := map[uint32]Identity{}
	for _, v := range all {
		byPID[v.PID] = v
	}
	seen := map[uint32]bool{}
	cur := child
	for n := 0; n < 16; n++ {
		if cur.ParentPID == 0 || cur.ParentCreationTime == 0 || seen[cur.ParentPID] {
			return false
		}
		seen[cur.ParentPID] = true
		parent, ok := byPID[cur.ParentPID]
		if !ok || parent.CreationTime != cur.ParentCreationTime || parent.CreationTime > cur.CreationTime {
			return false
		}
		if p.Matches(parent) {
			return true
		}
		cur = parent
	}
	return false
}

func packageFamily(folder string) (string, bool) {
	parts := strings.Split(folder, "_")
	if len(parts) < 5 {
		return "", false
	}
	version := parts[1]
	dots := 0
	if version == "" {
		return "", false
	}
	for _, c := range version {
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return "", false
		}
	}
	if dots != 3 || parts[0] == "" || parts[len(parts)-1] == "" {
		return "", false
	}
	return parts[0] + "_" + parts[len(parts)-1], true
}

// A curated helper inside this exact install/package is application-specific,
// including SCM-launched helpers which have no surviving GUI ancestor. This
// never trusts a basename outside the selected install or a different package.
func (a ApplicationIdentity) HelperInInstall(i Identity) bool {
	p := normalize(i.Path)
	root := strings.TrimSuffix(normalize(a.Root), "/")
	if !strings.HasPrefix(p, root+"/") {
		return false
	}
	if a.PackageFamily != "" {
		relative := strings.TrimPrefix(p, root+"/")
		slash := strings.IndexByte(relative, '/')
		if slash < 0 {
			return false
		}
		family, ok := packageFamily(relative[:slash])
		return ok && family == a.PackageFamily
	}
	return true
}
