package windowsplatform

type GameUDPGuardStatus struct {
	VanguardDriverRunning bool     `json:"vanguard_driver_running"`
	VanguardClientRunning bool     `json:"vanguard_client_running"`
	FaceitDriverRunning   bool     `json:"faceit_driver_running"`
	FaceitClientRunning   bool     `json:"faceit_client_running"`
	AntiCheatQueryError   string   `json:"anti_cheat_query_error,omitempty"`
	DriverAntiCheat       string   `json:"driver_anti_cheat,omitempty"`
	ForeignPIDs           []uint32 `json:"foreign_pids"`
	Ready                 bool     `json:"ready"`
	Conflict              bool     `json:"conflict"`
	ForeignHandles        int      `json:"foreign_handles"`
	Error                 string   `json:"error,omitempty"`
}
