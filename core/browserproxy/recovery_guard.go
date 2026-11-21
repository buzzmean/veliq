package browserproxy

import (
	"encoding/json"
	"io"
	"strings"
)

// Non-secret, owner-readable policy published atomically by the privileged
// service before/after policy transactions. It never contains device material.
// A missing, changing, oversized or invalid file denies emergency DIRECT.
type RecoveryGuard struct {
	DirectCompatibility bool                            `json:"direct_compatibility,omitempty"`
	Version             int                             `json:"version"`
	Deny                bool                            `json:"deny"`
	Profiles            map[string]RecoveryGuardProfile `json:"profiles"`
}
type RecoveryGuardProfile struct {
	Executables []string `json:"executables"`
	Domains     []string `json:"domains"`
	Strict      bool     `json:"strict"`
}

func recoveryDirectAuthorized(cfg RecoverySettings, host string) bool {
	allow, _ := recoveryDirectPolicy(cfg, host)
	return allow
}
func recoveryCompatibilityAuthorized(cfg RecoverySettings) bool {
	_, compatibility := recoveryDirectPolicy(cfg, "")
	return compatibility
}
func recoveryDirectPolicy(cfg RecoverySettings, host string) (bool, bool) {
	if cfg.GuardFile == "" {
		return true, false
	} // unit embedders; production CLI requires it.
	file, err := openRecoveryGuard(cfg.GuardFile)
	if err != nil {
		return false, false
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return false, false
	}
	var guard RecoveryGuard
	if json.Unmarshal(raw, &guard) != nil || guard.Version != 1 || guard.Deny || len(guard.Profiles) > 128 {
		return false, false
	}
	profile, ok := guard.Profiles[cfg.Profile]
	if !ok || len(profile.Executables) > 16 || len(profile.Domains) > 512 {
		return false, false
	}
	matches := false
	for _, exe := range profile.Executables {
		if strings.EqualFold(strings.ReplaceAll(exe, "\\", "/"), strings.ReplaceAll(cfg.Executable, "\\", "/")) {
			matches = true
		}
	}
	if !matches {
		return false, false
	}
	if guard.DirectCompatibility {
		return true, true
	}
	if profile.Strict {
		return false, false
	}
	for _, domain := range profile.Domains {
		canonical, err := CanonicalHost(domain)
		if err != nil || host == canonical || strings.HasSuffix(host, "."+canonical) {
			return false, false
		}
	}
	return true, false
}
