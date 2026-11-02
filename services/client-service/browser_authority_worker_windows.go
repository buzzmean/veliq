//go:build windows

package clientservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// WinINET must see the installation owner's primary token. Executable and flag
// are fixed; configuration is private stdin, never command-line text or logs.
func exchangeOwnerProxy(ctx context.Context, command wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
	binary, err := os.Executable()
	if err != nil {
		return wp.OwnerProxyState{}, errors.New("OWNER_PROXY_WORKER_UNAVAILABLE")
	}
	return exchangeOwnerProxyWithBinary(ctx, command, binary)
}
func exchangeOwnerProxyWithBinary(ctx context.Context, command wp.OwnerProxyCommand, binary string) (wp.OwnerProxyState, error) {
	raw, err := json.Marshal(command)
	if err != nil {
		return wp.OwnerProxyState{}, errors.New("OWNER_PROXY_COMMAND_INVALID")
	}
	child := exec.CommandContext(ctx, binary, "-owner-system-proxy")
	child.Stdin = bytes.NewReader(raw)
	child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if !tokenMatchesOwnerForProxy(windows.GetCurrentProcessToken(), command.Owner) {
		token, err := ownerProxySessionToken(command.Owner)
		if err != nil {
			return wp.OwnerProxyState{}, err
		}
		defer token.Close()
		child.SysProcAttr.Token = syscall.Token(token)
		child.Env, err = token.Environ(false)
		if err != nil {
			return wp.OwnerProxyState{}, errors.New("OWNER_PROXY_OWNER_ENVIRONMENT_UNAVAILABLE")
		}
	}
	output, err := child.Output()
	if err != nil || len(output) > 512*1024 {
		return wp.OwnerProxyState{}, errors.New("OWNER_PROXY_WORKER_FAILED")
	}
	var reply wp.OwnerProxyReply
	if json.Unmarshal(output, &reply) != nil {
		return wp.OwnerProxyState{}, errors.New("OWNER_PROXY_WORKER_REPLY_INVALID")
	}
	if reply.Error != "" {
		return wp.OwnerProxyState{}, errors.New(reply.Error)
	}
	return reply.State, nil
}
func tokenMatchesOwnerForProxy(token windows.Token, sid string) bool {
	u, err := token.GetTokenUser()
	return err == nil && u.User.Sid.String() == sid
}
func ownerProxySessionToken(sid string) (windows.Token, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count) != nil {
		return 0, errors.New("OWNER_PROXY_NO_OWNER_SESSION")
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	if count > 256 || (sessions == nil && count != 0) {
		return 0, errors.New("OWNER_PROXY_SESSION_LIMIT")
	}
	for _, s := range unsafe.Slice(sessions, count) {
		if s.State != windows.WTSActive && s.State != windows.WTSDisconnected {
			continue
		}
		var token windows.Token
		if windows.WTSQueryUserToken(s.SessionID, &token) != nil {
			continue
		}
		if tokenMatchesOwnerForProxy(token, sid) {
			return token, nil
		}
		token.Close()
	}
	return 0, errors.New("OWNER_PROXY_NO_OWNER_SESSION")
}
