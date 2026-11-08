package originpolicy

import "testing"

func TestGeminiPolicyDoesNotCaptureAllGoogle(t *testing.T) {
	for _, host := range []string{"gemini.google.com", "GEMINI.GOOGLE.COM.", "aistudio.google.com", "generativelanguage.googleapis.com", "alkalimakersuite-pa.clients6.google.com", "alkalimakersuite-pa.googleapis.com"} {
		if r := Floor(host); r.Kind != "RELAY" || r.Group != "gemini" {
			t.Fatal(host, r)
		}
	}
	for _, host := range []string{"google.com", "accounts.google.com", "mail.google.com", "googleapis.com", "storage.googleapis.com", "www.google.com", "gemini.google.com.attacker.example", "notgemini.google.com"} {
		if r := Floor(host); r.Group == "gemini" {
			t.Fatal("overbroad Gemini route", host, r)
		}
	}
	if r := Floor("rr1.googlevideo.com"); r.Group != "youtube-media" || r.Kind != "DPI" {
		t.Fatal("video route changed", r)
	}
	if err := Bundled().Validate(); err != nil {
		t.Fatal(err)
	}
}
