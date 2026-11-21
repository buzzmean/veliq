package clientservice

import "time"

const cdnNeutralShortLimit = 3

// Per-exposure release metadata: a terminated trial need not wait for both
// browser copy goroutines/Close; its established TCP is never moved or replayed.
type cdnTrialSlot struct {
	TrialID             uint64    `json:"trial_id"`
	SlotReleasedAt      time.Time `json:"slot_released_at"`
	SlotReleaseReason   string    `json:"slot_release_reason,omitempty"`
	NeutralShortAttempt uint32    `json:"neutral_short_attempt"`
	CooldownUntil       time.Time `json:"cooldown_until"`
}

func (r *youtubeRuntime) releaseTrialSlotLocked(slot cdnTrialSlot) {
	if v, ok := r.records[r.trialRecord]; ok {
		v.cdnTrialSlot = slot
		r.records[r.trialRecord] = v
	}
	r.selection.cdnTrialSlot = slot
	r.trialID = 0
	r.trialEndpoint = cdnEndpoint{}
	r.trialActive = false
	r.trialKey = youtubeKey{}
	r.trialStrategy = ""
	r.trialRecord = 0
	r.selection.ActiveTrial = false
}

func (r *youtubeRuntime) cacheAttempt(k youtubeKey) uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cache[k].NeutralShortStreak + 1
}
