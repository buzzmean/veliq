// Package clientconfig holds the installed wire manifest and its side-effect-free
// runtime defaults. Service and owner tools must not maintain divergent copies.
package clientconfig

import (
	"errors"
	"github.com/buzzmean/veliq/core/security"
	windowsplatform "github.com/buzzmean/veliq/platform/windows"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

type Manifest struct {
	// PersonalOptimizationLeaseStage is deliberately opt-in for an isolated test
	// installation. Existing paid, lifetime and club installations keep their
	// current behavior; this is not a production rollout switch.
	PersonalOptimizationLeaseStage bool                        `json:"personal_optimization_lease_stage,omitempty"`
	ClubImage                      bool                        `json:"club_image,omitempty"`
	ClubBrowserPaths               []string                    `json:"club_browser_paths,omitempty"`
	ActivationCodeFile             string                      `json:"activation_code_file,omitempty"`
	ActivationCAFingerprint        string                      `json:"activation_ca_sha256,omitempty"`
	ProbeTokenFile                 string                      `json:"probe_token_file,omitempty"`
	ControlPlaneCAFile             string                      `json:"control_plane_ca_file,omitempty"`
	OwnerSID                       string                      `json:"owner_sid"`
	TokenFile                      string                      `json:"token_file"`
	StateDirectory                 string                      `json:"state_directory"`
	ControlPlaneURL                string                      `json:"control_plane_url"`
	TrustFile                      string                      `json:"trust_file"`
	DeviceIdentityFile             string                      `json:"device_identity_file"`
	DeviceCertificate              string                      `json:"device_certificate"`
	CAFile                         string                      `json:"ca_file"`
	ProbeTarget                    string                      `json:"probe_target"`
	TCPProbeTarget                 string                      `json:"tcp_probe_target"`
	Driver                         windowsplatform.DriverFiles `json:"driver"`
}

func Normalize(m Manifest) Manifest {
	if m.ProbeTokenFile == "" && m.DeviceIdentityFile != "" {
		m.ProbeTokenFile = filepath.Join(filepath.Dir(m.DeviceIdentityFile), "probe.token")
	}
	// Legacy activation manifests omitted echo settings. Keep an explicit target;
	// otherwise use the same control-plane host's authenticated echo service.
	if m.ProbeTarget == "" {
		if u, err := url.Parse(m.ControlPlaneURL); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil {
			m.ProbeTarget = net.JoinHostPort(u.Hostname(), "40000")
		}
	}
	return m
}
func Load(path string) (Manifest, error) {
	var m Manifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err = security.Parse(raw, &m); err != nil {
		return m, err
	}
	if !filepath.IsAbs(m.TokenFile) || !filepath.IsAbs(m.StateDirectory) {
		return m, errors.New("absolute token and state paths required")
	}
	return Normalize(m), nil
}
