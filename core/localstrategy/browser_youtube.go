package localstrategy

// BrowserYouTubeCandidates adds bounded native-only plans without changing
// existing saved presets or their revisions. This is original packet code;
// no upstream binary/fake payload, autottl, MD5 option or invalid checksum.
func BrowserYouTubeCandidates() []Candidate {
	out := []Candidate{}
	for _, ttl := range []uint8{5, 8} {
		name := "fake5x2-disorder"
		if ttl == 8 {
			name = "fake8x2-disorder"
		}
		out = append(out, Candidate{ID: name, Actions: []Action{{Kind: "fake-tls", TTL: ttl, Repeats: 2}, {Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1, 5}}, {Kind: "tcp-disorder"}}})
	}
	return append(out, candidates()...)
}
