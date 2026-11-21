//go:build !windows

package main

import (
	"context"
)

func platformRun(ctx context.Context, path string, console bool) error { return run(ctx, path) }
