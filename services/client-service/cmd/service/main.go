package main

import (
	"context"
	"errors"
	"flag"
	"github.com/buzzmean/neexitlag/core/ipc"
	"github.com/buzzmean/neexitlag/core/emergency"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
	clientservice "github.com/buzzmean/neexitlag/services/client-service"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func run(ctx context.Context, path string) error { return runReady(ctx, path, nil) }
func runReady(ctx context.Context, path string, ready func()) error {
	ctx,cancelHost:=context.WithCancel(ctx)
	defer cancelHost()
	initCtx,cancelInit:=context.WithCancel(ctx)
	defer cancelInit()
	manifest, e := clientservice.LoadManifest(path)
	if e != nil {
		return e
	}
	token, e := os.ReadFile(manifest.TokenFile)
	if e != nil {
		return e
	}
	// Host cancellation reaches CloseForHost first: remove PAC before cancelling listeners.
	controller := clientservice.New(context.WithoutCancel(ctx))
	defer func() {
		if err := controller.CloseForHost(ctx); err != nil {
			slog.Warn("owned browser policy cleanup incomplete", "class", "BROWSER_POLICY_CLEANUP_FAILED")
		}
	}()

	controller.BrowserOwnerSID = manifest.OwnerSID
	controller.Backend = windowsplatform.NewWinDivert(manifest.Driver, controller.Engine)
	if e = controller.SetCustomPath(manifest.StateDirectory + string(os.PathSeparator) + "profiles.json"); e != nil {
		return e
	}
	if e = controller.ConfigureClub(manifest); e != nil {
		return e
	}
	{ // Every boot, including freeze: remove only journal-owned stale policy before initialization.
		if err := controller.CleanupOwnedBrowserPolicies(); err != nil {
			slog.Warn("preactivation owned browser policy cleanup incomplete", "class", "BROWSER_POLICY_CLEANUP_FAILED")
		}
	}
	managedActivation := controller.ConfigureActivation(manifest)
	if err := controller.RestoreOwnerAuthorityListener(); err != nil {
		slog.Warn("owned CONNECT listener restore incomplete", "class", "AUTHORITY_LISTENER_RESTORE_FAILED")
	}
	// The pipe opens before the slow stages so SCM does not wait on the network and
	// the GUI can tell "starting" from "not installed". Methods are rejected until
	// initialization finishes (see startupGate).
	var gate startupGate
	initDone := make(chan struct{})
	emergencyManager:=emergency.NewManager(emergency.New(manifest.OwnerSID,windowsplatform.ReadEmergencyVerifier),func()error{
		controller.BeginEmergencyStop()
		cancelInit()
		<-initDone
		return controller.FinishEmergencyStop()
	})
	emergencyManager.IdleStatus=func()any{return controller.Snapshot()}
	server, e := ipc.New(strings.TrimSpace(string(token)), emergencyManager.Wrap(gate.wrap(controller.HandleOwnerIPC)))
	if e != nil {
		return e
	}
	server.AfterReply=func(method string,reply ipc.Response,writeError error){
		if method=="emergency.finish" && reply.OK && writeError==nil {cancelHost()}
	}
	listener, e := clientservice.ListenIPC(manifest.OwnerSID)
	if e != nil {
		return e
	}
	defer listener.Close()
	go func() {
		defer close(initDone)
		if initCtx.Err()!=nil {return}
		// Restore listener and owned PAC before remote CP/network initialization.
		// A code-managed boot restores policy only after binding/authentication;
		// its activation worker owns that transition, never this parallel stage.
		if !managedActivation {
			if e := controller.RestoreBrowserTransport(); e != nil {
				slog.Warn("Chrome transport not restored; proxy remains fail-closed", "error", e)
			}
		}
		if manifest.ControlPlaneURL != "" && !managedActivation {
			if e := controller.ConnectRemote(initCtx, manifest); e != nil {
				slog.Warn("control plane initialization unavailable; capture remains DIRECT", "error", e)
			}
		}
		if initCtx.Err()!=nil {return}
		controller.Start()
		if !managedActivation && controller.Snapshot().Settings.Automatic {
			if _, e := controller.Handle(ctx, "optimize", []byte(`{"enabled":true}`)); e != nil {
				slog.Warn("automatic capture unavailable; networking remains DIRECT", "error", e)
			}
		}
		gate.ready.Store(true)
		slog.Info("service initialization complete")
	}()
	defer func() { cancelInit(); <-initDone }() // cancelled ctx unblocks the stages; Close must not race them
	if ready != nil {
		ready()
	}
	return clientservice.ServeIPC(ctx, listener, server)
}
func main() {
	ownerProxy := flag.Bool("owner-system-proxy", false, "owner-user WinINET worker; private stdin, no service credentials")
	recovery := flag.Bool("chrome-recovery", false, "owner-scoped Chrome recovery transport; no service privileges or credentials")
	recoveryPort := flag.Uint("recovery-port", 0, "persisted IPv4 loopback recovery port")
	path := flag.String("config", "", "absolute service manifest path")
	watchdog := flag.Bool("browser-policy-watchdog", false, "independent owned policy cleanup; no capture/enroll/Internet")
	cleanup := flag.Bool("cleanup-browser-policy", false, "remove only journal-owned browser policies; no capture/enrollment/network")
	console := flag.Bool("console", false, "run as an interactive service host for diagnostics")
	flag.Parse()
	if *ownerProxy {
		if runOwnerSystemProxy(os.Stdin, os.Stdout) != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()
	role := "SERVICE_HOST"
	if *console {
		role = "CONSOLE_HOST"
	}
	if *watchdog {
		role = "POLICY_WATCHDOG"
	}
	if *cleanup {
		role = "POLICY_CLEANUP"
	}
	if *recovery {
		role = "OWNER_RECOVERY"
	}
	slog.Info("VELIQ process role", "role", role, "pid", os.Getpid(), "parent_pid", os.Getppid())
	if *watchdog {
		if err := clientservice.RunBrowserPolicyWatchdog(ctx, *path); err != nil {
			slog.Error("policy watchdog unavailable", "class", "WATCHDOG_FAILED")
			os.Exit(1)
		}
		return
	}
	if *cleanup {
		manifest, err := clientservice.LoadManifest(*path)
		if err == nil {
			c := clientservice.New(ctx)
			c.BrowserOwnerSID = manifest.OwnerSID
			err = c.SetCustomPath(manifest.StateDirectory + string(os.PathSeparator) + "profiles.json")
			if err == nil {
				err = errors.Join(c.RestoreOwnerBrowserProxy(), c.CleanupOwnedBrowserPolicies())
			}
			c.Close()
		}
		if err != nil {
			slog.Error("browser policy cleanup failed", "class", "BROWSER_POLICY_CLEANUP_FAILED")
			os.Exit(1)
		}
		slog.Info("owned browser policies removed or absent; foreign settings preserved")
		return
	}
	if *recovery {
		if *recoveryPort > 65535 {
			os.Exit(1)
		}
		if err := runBrowserRecovery(ctx, uint16(*recoveryPort)); err != nil {
			slog.Error("Chrome recovery stopped", "class", "RECOVERY_START_FAILED")
			os.Exit(1)
		}
		return
	}
	if e := platformRun(ctx, *path, *console); e != nil {
		slog.Error("client service stopped", "error", e)
		os.Exit(1)
	}
}
