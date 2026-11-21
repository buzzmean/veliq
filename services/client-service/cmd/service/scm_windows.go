//go:build windows

package main

import (
	"context"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
	"golang.org/x/sys/windows/svc"
	"time"
)

type handler struct {
	path   string
	parent context.Context
}

func (h handler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	status <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() { done <- runReady(ctx, h.path, func() { close(ready) }) }()
	for {
		select {
		case <-ready:
			ready = nil
			status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
		case e := <-done:
			if e != nil {
				return false, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.Cmd(128):
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, policyStopExitCode(r.Cmd)
			}
		}
	}
}
func platformRun(ctx context.Context, path string, console bool) error {
	if console {
		return run(ctx, path)
	}
	service, e := svc.IsWindowsService()
	if e != nil {
		return e
	}
	if !service {
		return run(ctx, path)
	}
	return svc.Run(windowsplatform.ServiceName, handler{path, ctx})
}

func policyStopExitCode(cmd svc.Cmd) uint32 {
	if cmd == svc.Cmd(128) {
		return 1
	}
	return 0
}
