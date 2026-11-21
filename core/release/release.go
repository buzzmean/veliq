// Package release describes a signed VELIQ release published on GitHub Releases.
// The manifest is signed with the control-plane config key (domain "release");
// the Setup binary itself is bound by size and SHA-256.
package release

import (
	"encoding/hex"
	"errors"
	"regexp"
)

const Domain = "release"

// ManifestAsset and SetupAsset are the GitHub release asset names.
const ManifestAsset = "veliq-release.json"
const SetupAsset = "VELIQ-Setup.exe"

// MaxSetupSize bounds the download; the current Setup is ~100 MiB.
const MaxSetupSize = 512 << 20

type Manifest struct {
	// Build is monotonic (git commit count of the release commit); clients
	// install only a strictly newer build than their own.
	Build       uint64 `json:"build"`
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	SetupSize   int64  `json:"setup_size"`
	SetupSHA256 string `json:"setup_sha256"`
}

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var versionPattern = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,32}$`)

func (m Manifest) Validate() error {
	sum, e := hex.DecodeString(m.SetupSHA256)
	if m.Build == 0 || !commitPattern.MatchString(m.Commit) || !versionPattern.MatchString(m.Version) || e != nil || len(sum) != 32 || m.SetupSize <= 0 || m.SetupSize > MaxSetupSize {
		return errors.New("invalid release manifest")
	}
	return nil
}
