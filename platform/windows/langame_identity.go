package windowsplatform

import (
	"strings"
	"sync"
	"time"
)

type lanGameVerdict struct {
	identity ProcessIdentity
	trusted  bool
	expires  time.Time
}

type lanGameCacheSlot struct {
	mu      sync.Mutex
	verdict lanGameVerdict
}

type lanGameIdentityCache struct {
	slots [32]lanGameCacheSlot
}

var lanGameOwners lanGameIdentityCache

// IsLanGameServiceProcess recognizes the SCM-owned service and its same-image
// direct worker in the interactive session. An executable name alone grants
// no exemption. Network callers obtain the PID, creation time and image path
// from their existing kernel-backed owner lookup.
func IsLanGameServiceProcess(id ProcessIdentity) bool {
	base := strings.LastIndexAny(id.Path, `\/`)
	if id.PID == 0 || id.CreationTime == 0 || base < 0 || !strings.EqualFold(id.Path[base+1:], "LanGameService.exe") {
		return false
	}
	return lanGameOwners.match(id, time.Now(), verifyLanGameOwner)
}

func sameLanGameInstance(a, b ProcessIdentity) bool {
	return a.PID != 0 && a.PID == b.PID && a.CreationTime != 0 && a.CreationTime == b.CreationTime &&
		a.Path != "" && strings.EqualFold(a.Path, b.Path)
}

func (c *lanGameIdentityCache) match(id ProcessIdentity, now time.Time, resolve func(ProcessIdentity) bool) bool {
	// A new process can reuse the same Windows PID. The birth time and path
	// must match even on a cache hit. Slots bound memory for lookalike names.
	slot := &c.slots[(id.PID/4)%uint32(len(c.slots))]
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if now.Before(slot.verdict.expires) && sameLanGameInstance(id, slot.verdict.identity) {
		return slot.verdict.trusted
	}
	trusted := resolve(id)
	ttl := time.Second
	if trusted {
		ttl = 30 * time.Second
	}
	slot.verdict = lanGameVerdict{identity: id, trusted: trusted, expires: now.Add(ttl)}
	return trusted
}

// Both live identities are read from Windows, including the worker's parent
// creation time. Some callers only carry the process's own identity.
func lanGameOwnershipMatches(request, live, service ProcessIdentity) bool {
	if !sameLanGameInstance(request, live) || service.PID == 0 || service.CreationTime == 0 || !strings.EqualFold(live.Path, service.Path) {
		return false
	}
	if live.PID == service.PID {
		return live.CreationTime == service.CreationTime
	}
	return live.ParentPID == service.PID && live.ParentCreationTime == service.CreationTime &&
		service.CreationTime <= live.CreationTime
}

// The SCM configuration can contain a quoted path or an unquoted path with
// spaces. Compare to the actual process image and require a complete argument
// boundary. A LanGame path appearing as an argument to a wrapper cannot match.
func lanGameConfiguredImage(command, image string) bool {
	command = strings.TrimSpace(command)
	if command == "" || image == "" {
		return false
	}
	if command[0] == '"' {
		path, rest, found := strings.Cut(command[1:], `"`)
		return found && strings.EqualFold(path, image) && (rest == "" || rest[0] == ' ' || rest[0] == '\t')
	}
	for i, r := range command {
		if (r == ' ' || r == '\t') && strings.EqualFold(command[:i], image) {
			return true
		}
	}
	return strings.EqualFold(command, image)
}

func lanGameManagerMatches(root, manager ProcessIdentity, systemImage, sid string, session uint32) bool {
	return root.ParentPID != 0 && root.ParentPID == manager.PID &&
		root.ParentCreationTime != 0 && root.ParentCreationTime == manager.CreationTime &&
		manager.CreationTime <= root.CreationTime && strings.EqualFold(manager.Path, systemImage) &&
		sid == "S-1-5-18" && session == 0
}
