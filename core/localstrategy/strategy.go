package localstrategy

// Built-in mechanism definitions contain no upstream payload/templates. A profile
// supplies matching, priority and cutoff independently of this packet algorithm.
// New profiles over these mechanisms require data changes, not capture changes.
type packetStrategy struct{ protocol, name string }

var _ LocalStrategy = packetStrategy{}

func (s packetStrategy) Match(m Metadata) bool { return m.Protocol == s.protocol }
func (s packetStrategy) Process(p []byte, state *State) Result {
	packets := transformAt(p, s.name, state.splitPosition)
	return Result{Packets: packets, Modified: len(packets) > 0}
}

var mechanisms = map[string]LocalStrategy{
	HTTP80HostSplit:   packetStrategy{"tcp", HTTP80HostSplit},
	"tcp-split":       packetStrategy{"tcp", "tcp-split"},
	"tcp-split-1":     packetStrategy{"tcp", "tcp-split-1"},
	"tcp-split-5":     packetStrategy{"tcp", "tcp-split-5"},
	"udp-fragment-24": packetStrategy{"udp", "udp-fragment-24"},
}
