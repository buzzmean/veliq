package localstrategy

import "testing"

func TestQUICProbeCatalogRemainsSeparateFromBrowserRuntime(t *testing.T) {
	c := BundledCatalog()
	plans, caps := c.QUICProbePlans()
	if len(plans) != 43 || len(caps) != 44 {
		t.Fatal("pinned catalog coverage changed", len(plans), len(caps))
	}
	for _, cap := range caps {
		if cap.BrowserRuntimeEnabled {
			t.Fatal("offline plan enabled browser QUIC")
		}
	}
	_, runtime := c.Compile()
	for _, plan := range plans {
		if plan.Repeats != 6 && plan.Repeats != 11 {
			t.Fatal("unexpected source repeats")
		}
		for _, cap := range runtime {
			if cap.Rule == plan.Rule && cap.Supported {
				t.Fatal("QUIC entered TCP runtime picker")
			}
		}
	}
	var source CatalogRule
	for _, r := range c.Rules {
		if r.ID == plans[0].Rule {
			source = r
			break
		}
	}
	for _, mutate := range []func(*CatalogRule){
		func(r *CatalogRule) { r.Options["filter-udp"] = []string{"443", "53"} },
		func(r *CatalogRule) { r.Options["filter-udp"] = []string{"443-65535"} },
		func(r *CatalogRule) { r.Options["dpi-desync-repeats"] = []string{"17"} },
		func(r *CatalogRule) { r.Options["dpi-desync-fake-quic"] = []string{"external.bin"} },
		func(r *CatalogRule) { r.Options["dpi-desync-fooling"] = []string{"badseq"} },
		func(r *CatalogRule) { r.Options["hostlist"] = []string{"arbitrary-hosts.txt"} },
		func(r *CatalogRule) { r.Applies = []string{"quic443", "tcp443"} },
	} {
		r := source
		r.Options = map[string][]string{}
		for k, v := range source.Options {
			r.Options[k] = append([]string(nil), v...)
		}
		mutate(&r)
		if _, reason := r.quicProbePlan(); reason == "" {
			t.Fatal("unknown parameter semantics silently accepted")
		}
	}
}
