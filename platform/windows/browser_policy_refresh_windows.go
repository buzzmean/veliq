//go:build windows

package windowsplatform

import (
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"syscall"
	"unsafe"
)

var refreshUserPolicyEx = windows.NewLazySystemDLL("userenv.dll").NewProc("RefreshPolicyEx")

func requestBrowserPolicyRefresh(sid string) {
	browserPolicyRefresh.request(sid, refreshOwnerUserPolicy)
}
func tokenMatchesOwner(token windows.Token, sid string) bool {
	u, e := token.GetTokenUser()
	return e == nil && u.User.Sid.String() == sid
}
func callUserPolicyRefresh() string {
	ok, _, e := refreshUserPolicyEx.Call(0, 1) // USER, RP_FORCE; async, no gpupdate/process/window.
	if ok == 0 {
		code, _ := e.(syscall.Errno)
		return fmt.Sprintf("USER_POLICY_REFRESH_FAILED_%d", uint32(code))
	}
	return "USER_POLICY_REFRESH_REQUESTED"
}
func refreshOwnerUserPolicy(sid string) string {
	result := make(chan string, 1)
	go func() { result <- refreshOwnerUserPolicyOnThread(sid) }()
	return <-result
}
func refreshOwnerUserPolicyOnThread(sid string) string {
	if _, e := windows.StringToSid(sid); e != nil {
		return "USER_POLICY_REFRESH_OWNER_INVALID"
	}
	if tokenMatchesOwner(windows.GetCurrentProcessToken(), sid) {
		return callUserPolicyRefresh()
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count) != nil {
		return "USER_POLICY_REFRESH_NO_OWNER_SESSION"
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	if count > 256 || (sessions == nil && count != 0) {
		return "USER_POLICY_REFRESH_SESSION_LIMIT"
	}
	for _, session := range unsafe.Slice(sessions, count) {
		var token windows.Token
		if windows.WTSQueryUserToken(session.SessionID, &token) != nil {
			continue
		}
		if !tokenMatchesOwner(token, sid) {
			token.Close()
			continue
		}
		var impersonation windows.Token
		e := windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation)
		token.Close()
		if e != nil {
			return "USER_POLICY_REFRESH_OWNER_TOKEN_FAILED"
		}
		defer impersonation.Close()
		// This dedicated goroutine must never return an impersonated thread to the
		// scheduler. A failed RevertToSelf leaves it locked; Go destroys it on exit.
		runtime.LockOSThread()
		if windows.SetThreadToken(nil, impersonation) != nil {
			runtime.UnlockOSThread()
			return "USER_POLICY_REFRESH_IMPERSONATION_FAILED"
		}
		state := callUserPolicyRefresh()
		if windows.RevertToSelf() != nil {
			return "USER_POLICY_REFRESH_REVERT_FAILED_THREAD_RETIRED"
		}
		runtime.UnlockOSThread()
		return state
	}
	return "USER_POLICY_REFRESH_NO_OWNER_SESSION"
}
