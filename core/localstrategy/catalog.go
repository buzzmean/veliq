package localstrategy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/originpolicy"
	"sort"
	"strconv"
	"strings"
)

const CatalogVersion = 1

// Data release is separate from schema: adding reviewed origin data changes the
// signed payload and must not equivocate under the old default release version.
const BundledCatalogRelease = 2
const CatalogMaxBytes = 256 * 1024

//go:embed catalog.json
var bundledCatalog []byte

type CatalogSource struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	License  string `json:"license"`
	URL      string `json:"url"`
}
type CatalogRule struct {
	ID       string              `json:"id"`
	Source   string              `json:"source"`
	Revision string              `json:"revision"`
	File     string              `json:"file"`
	Applies  []string            `json:"applies"`
	Options  map[string][]string `json:"options"`
}
type Catalog struct {
	Origins  *originpolicy.Registry `json:"origins,omitempty"`
	Version  int                    `json:"version"`
	Reviewed string                 `json:"reviewed"`
	Release  string                 `json:"flowseal_release"`
	Files    []string               `json:"flowseal_files"`
	Sources  []CatalogSource        `json:"sources"`
	Rules    []CatalogRule          `json:"rules"`
}
type CatalogPlan struct {
	Candidate
	Source     string `json:"source"`
	Rule       string `json:"rule"`
	Adaptation string `json:"adaptation"`
}
type CatalogCapability struct {
	Rule      string `json:"rule"`
	Source    string `json:"source"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason"`
	Plan      string `json:"plan,omitempty"`
}

func ParseCatalog(raw []byte) (Catalog, error) {
	var c Catalog
	if len(raw) == 0 || len(raw) > CatalogMaxBytes || json.Unmarshal(raw, &c) != nil || c.Version != CatalogVersion || len(c.Rules) == 0 || len(c.Rules) > 256 || len(c.Sources) > 8 || len(c.Files) > 64 {
		return c, errors.New("LOCAL_CATALOG_INVALID")
	}
	if c.Origins != nil {
		if err := c.Origins.Validate(); err != nil {
			return c, err
		}
	}
	sources := map[string]string{}
	seen := map[string]bool{}
	for _, s := range c.Sources {
		if s.ID == "" || len(s.ID) > 32 || sources[s.ID] != "" || s.License != "MIT" || len(s.Revision) != 40 || !strings.HasPrefix(s.URL, "https://github.com/") {
			return c, errors.New("LOCAL_CATALOG_SOURCE_INVALID")
		}
		sources[s.ID] = s.Revision
	}
	for _, r := range c.Rules {
		if r.ID == "" || len(r.ID) > 96 || seen[r.ID] || sources[r.Source] != r.Revision || len(r.Options) > 40 || len(r.File) > 256 || len(r.Applies) > 3 {
			return c, errors.New("LOCAL_CATALOG_RULE_INVALID")
		}
		seen[r.ID] = true
		for k, vs := range r.Options {
			if len(k) > 64 || len(vs) > 8 {
				return c, errors.New("LOCAL_CATALOG_PARAMETER_LIMIT")
			}
			for _, v := range vs {
				if len(v) > 256 || strings.ContainsAny(v, "\r\n\x00") {
					return c, errors.New("LOCAL_CATALOG_PARAMETER_INVALID")
				}
			}
		}
	}
	return c, nil
}
func BundledCatalog() Catalog {
	c, err := ParseCatalog(bundledCatalog)
	if err != nil {
		panic("invalid embedded local catalog")
	}
	if c.Origins == nil {
		r := originpolicy.Bundled()
		c.Origins = &r
	}
	return c
}
func (c Catalog) Compile() ([]CatalogPlan, []CatalogCapability) {
	plans := []CatalogPlan{}
	caps := []CatalogCapability{}
	seen := map[string]bool{}
	for _, r := range c.Rules {
		actions, reason := r.actions()
		capability := CatalogCapability{Rule: r.ID, Source: r.Source, Reason: reason}
		if reason == "" {
			raw, _ := json.Marshal(actions)
			sum := sha256.Sum256(raw)
			id := "catalog-" + hex.EncodeToString(sum[:8])
			capability.Supported = true
			capability.Plan = id
			capability.Reason = "OWN_TCP_ADAPTATION_NOT_UPSTREAM_BINARY_EQUIVALENCE"
			if !seen[id] {
				seen[id] = true
				plans = append(plans, CatalogPlan{Candidate: Candidate{ID: id, Actions: actions}, Source: r.Source, Rule: r.ID, Adaptation: "own payloads; typed TCP recipes; browser-only bounded first flight; wire proof required"})
			}
		}
		caps = append(caps, capability)
	}
	// Stable source order is only the prior; measured network success ranks above it.
	sort.SliceStable(plans, func(i, j int) bool { return plans[i].Source == "flowseal" && plans[j].Source != "flowseal" })
	if len(plans) > 48 {
		plans = plans[:48]
	}
	return plans, caps
}
func (r CatalogRule) actions() ([]Action, string) {
	tcp := false
	for _, v := range r.Applies {
		tcp = tcp || v == "tcp443"
	}
	if !tcp {
		return nil, "HTTP_OR_QUIC_NOT_IMPLEMENTED; QUIC_USES_TCP_FALLBACK"
	}
	if r.Source == "flowseal" {
		return compileNativeTCP(r)
	}
	get := func(k string) string {
		vs := r.Options[k]
		if len(vs) == 0 {
			return ""
		}
		return vs[len(vs)-1]
	}
	for _, k := range []string{"dpi-desync-hostfakesplit-mod", "dpi-desync-fakedsplit-pattern", "dpi-desync-badseq-increment"} {
		if get(k) != "" {
			return nil, "UNSUPPORTED_PARAMETER_" + k
		}
	}
	mode := get("dpi-desync")
	if mode != "fake" && mode != "fake,multisplit" && mode != "fake,multidisorder" && mode != "multisplit" && mode != "multidisorder" {
		return nil, "UNSUPPORTED_MODE_" + mode
	}
	out := []Action{}
	if strings.Contains(mode, "fake") {
		repeat := uint64(1)
		if n := get("dpi-desync-repeats"); n != "" {
			var err error
			repeat, err = strconv.ParseUint(n, 10, 8)
			if err != nil || repeat < 1 || repeat > 16 {
				return nil, "REPEATS_OUTSIDE_1_16"
			}
		}
		model := "tls13-google"
		if strings.Contains(get("dpi-desync-fake-tls-mod"), "sni=ya.ru") {
			model = "tls13-yandex"
		}
		fooling := get("dpi-desync-fooling")
		if fooling == "" {
			fooling = "badseq"
		}
		out = append(out, Action{Kind: "fake-tls", TTL: 16, Repeats: uint8(repeat), FakeModel: model, Fooling: fooling, AutoTTL: get("dpi-desync-autottl") != ""})
	}
	if strings.Contains(mode, "split") || strings.Contains(mode, "disorder") {
		positions := get("dpi-desync-split-pos")
		if positions == "" {
			positions = "1,midsld"
		}
		split := Action{Kind: "tcp-multisplit", Markers: strings.Split(positions, ",")}
		if value := get("dpi-desync-split-seqovl"); value != "" {
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil || n < 256 || n > 1024 {
				return nil, "UNSUPPORTED_SEQOVL_SIZE"
			}
			split.SequenceOverlap = uint16(n)
		}
		out = append(out, split)
		if strings.Contains(mode, "disorder") {
			out = append(out, Action{Kind: "tcp-disorder"})
		}
	}
	test := Profile{Preset: "browser-catalog", Application: "chrome.exe", Protocol: "tcp", Ports: []uint16{443}, Cutoff: 1, Actions: out}
	if validateChain(test) != nil {
		return nil, "UNSUPPORTED_OR_UNBOUNDED_ACTION_PLAN"
	}
	return out, ""
}
