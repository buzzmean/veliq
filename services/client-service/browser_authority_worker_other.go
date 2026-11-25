//go:build !windows

package clientservice

import (
	"context"
	"errors"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func exchangeOwnerProxy(context.Context, wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
	return wp.OwnerProxyState{}, errors.New("OWNER_PROXY_WINDOWS_REQUIRED")
}
