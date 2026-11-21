// Package releaseinfo reports bounded, non-secret runtime upgrade capabilities.
package releaseinfo

import (
	"encoding/json"
	"io"
	"runtime/debug"
)

type Info struct {
	Role            string   `json:"role"`
	Commit          string   `json:"commit"`
	Modified        bool     `json:"modified"`
	Protocols       []string `json:"protocols,omitempty"`
	MaxConfigBytes  int      `json:"max_config_bytes"`
	LeaseSeconds    int      `json:"default_lease_seconds,omitempty"`
	FullRevocations bool     `json:"full_revocations"`
	Migration       string   `json:"migration"`
}

func Current(role string, protocols []string, maxConfig, leaseSeconds int) Info {
	out := Info{Role: role, Protocols: protocols, MaxConfigBytes: maxConfig, LeaseSeconds: leaseSeconds, FullRevocations: true, Migration: "001-additive"}
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			switch s.Key {
			case "vcs.revision":
				out.Commit = s.Value
			case "vcs.modified":
				out.Modified = s.Value != "false"
			}
		}
	}
	return out
}
func Write(w io.Writer, role string, protocols []string, maxConfig, leaseSeconds int) error {
	return json.NewEncoder(w).Encode(Current(role, protocols, maxConfig, leaseSeconds))
}
