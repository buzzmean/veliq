package originpolicy

import "testing"

func TestReviewedPolicyGroupsAndOrdinaryDefaults(t *testing.T) {
	d := Bundled()
	if e := d.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct{ host, kind, group string }{{"kws2-1.web.telegram.org", "RELAY", "telegram"}, {"bridge.claudeusercontent.com", "RELAY", "anthropic"}, {"chatgpt.com", "RELAY", "openai"}, {"instagram.com", "RELAY", "meta"}, {"rr1---sn-abc.googlevideo.com", "DPI", "youtube-media"}, {"gateway.discord.gg", "DPI", "discord"}, {"rutracker.org", "DPI", "rutracker"}, {"x.com", "DPI", "x"}, {"google.com", "", ""}, {"vk.ru", "", ""}, {"yandex.ru", "", ""}, {"chatgpt.com.evil.example", "", ""}} {
		got := d.Lookup(v.host)
		if got.Kind != v.kind || got.Group != v.group {
			t.Fatal(v, got)
		}
	}
}
func TestUpdatesCannotWeakenRelayFloorsOrNestedSubdomains(t *testing.T) {
	for _, host := range []string{"chatgpt.com", "telegram.org", "claude.ai"} {
		d := Bundled()
		d.Rules = append(d.Rules, Rule{Group: "override", Kind: "DPI", Suffixes: []string{"child." + host}})
		if d.Validate() == nil {
			t.Fatal("nested protected downgrade", host)
		}
	}
	d := Bundled()
	for i := range d.Rules {
		if d.Rules[i].Group == "openai" {
			d.Rules[i].Kind = "DPI"
			d.Rules[i].Protected = false
		}
	}
	if d.Validate() == nil {
		t.Fatal("floor removed")
	}
	d = Bundled()
	d.Rules[0].Suffixes[0] = "mutated.example"
	if Floor("chatgpt.com").Kind != "RELAY" {
		t.Fatal("bundled global state was mutable")
	}
}
