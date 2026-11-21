// Package originpolicy stores reviewed domain-group DATA. DPI classification
// does not imply a working transform; RELAY security floors cannot be weakened.
package originpolicy

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
)

//go:embed registry.json
var bundled []byte

var defaults = func() Registry {
	var d Registry
	if json.Unmarshal(bundled, &d) != nil {
		panic("invalid bundled origin data")
	}
	return d
}()

type Rule struct {
	Group     string   `json:"group"`
	Kind      string   `json:"kind"`
	Protected bool     `json:"protected,omitempty"`
	Suffixes  []string `json:"suffixes"`
}
type Registry struct {
	Version  uint64 `json:"version"`
	Reviewed string `json:"reviewed"`
	Source   string `json:"source"`
	Rules    []Rule `json:"rules"`
}

func Bundled() Registry {
	d := defaults
	d.Rules = append([]Rule(nil), defaults.Rules...)
	for i := range d.Rules {
		d.Rules[i].Suffixes = append([]string(nil), defaults.Rules[i].Suffixes...)
	}
	return d
}
func Match(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}
func (d Registry) Lookup(host string) Rule {
	var found Rule
	longest := 0
	for _, r := range d.Rules {
		for _, suffix := range r.Suffixes {
			if len(suffix) > longest && Match(host, suffix) {
				longest = len(suffix)
				found = r
			}
		}
	}
	return found
}
func (d Registry) Validate() error {
	if d.Version == 0 || len(d.Rules) == 0 || len(d.Rules) > 64 || len(d.Reviewed) != 10 || len(d.Source) > 512 {
		return errors.New("ORIGIN_DATA_INVALID")
	}
	seen := map[string]bool{}
	for _, r := range d.Rules {
		if len(r.Group) == 0 || len(r.Group) > 32 || (r.Kind != "DPI" && r.Kind != "RELAY") || r.Protected && r.Kind != "RELAY" || len(r.Suffixes) == 0 || len(r.Suffixes) > 64 {
			return errors.New("ORIGIN_RULE_INVALID")
		}
		for _, c := range r.Group {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("ORIGIN_GROUP_INVALID")
			}
		}
		for _, h := range r.Suffixes {
			if len(h) < 3 || len(h) > 253 || h != strings.ToLower(h) || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") || seen[h] {
				return errors.New("ORIGIN_SUFFIX_INVALID")
			}
			for _, c := range h {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
					return errors.New("ORIGIN_SUFFIX_INVALID")
				}
			}
			for _, label := range strings.Split(h, ".") {
				if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return errors.New("ORIGIN_SUFFIX_INVALID")
				}
			}
			seen[h] = true
		}
	}
	// The immutable bundled IP/geo protection is a lower bound even for signed
	// updates. Nested DPI exceptions must not weaken a protected family.
	for _, floor := range Bundled().Rules {
		if floor.Kind != "RELAY" {
			continue
		}
		for _, h := range floor.Suffixes {
			got := d.Lookup(h)
			if got.Kind != "RELAY" || floor.Protected && !got.Protected {
				return errors.New("ORIGIN_SECURITY_FLOOR_REQUIRED")
			}
			for _, r := range d.Rules {
				for _, nested := range r.Suffixes {
					if Match(nested, h) && (r.Kind != "RELAY" || floor.Protected && !r.Protected) {
						return errors.New("ORIGIN_SECURITY_FLOOR_EXCEPTION")
					}
				}
			}
		}
	}
	return nil
}
func Floor(host string) Rule { r := defaults.Lookup(host); r.Suffixes = nil; return r }
