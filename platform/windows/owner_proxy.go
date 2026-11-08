package windowsplatform

// OwnerProxyState is configuration, not diagnostic output. Never log its URLs.
// WinINET operations run in the owner's primary process token, never SYSTEM
// impersonation: WinINET maintains process-local user configuration caches.
type OwnerProxyState struct {
	Flags  uint32 `json:"flags"`
	PAC    string `json:"pac"`
	Server string `json:"server"`
	Bypass string `json:"bypass"`
}

// OwnerProxyCommand is exchanged only through a private child stdin/stdout.
// It provides no service credentials, file access, enrollment or privileged RPC.
type OwnerProxyCommand struct {
	Owner    string           `json:"owner"`
	Expected *OwnerProxyState `json:"expected,omitempty"`
	Desired  *OwnerProxyState `json:"desired,omitempty"`
}
type OwnerProxyReply struct {
	State OwnerProxyState `json:"state"`
	Error string          `json:"error,omitempty"`
}
