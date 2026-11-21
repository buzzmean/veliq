package browserfixture

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestChromeProcessWaitChild(t *testing.T) {
	mode := os.Getenv("NEEXITLAG_TEST_CHROME_WAIT")
	if mode == "" {
		t.Skip("redirected process regression child")
	}
	release := os.Getenv("NEEXITLAG_TEST_CHROME_RELEASE")
	if mode == "hold" {
		fmt.Fprintln(os.Stdout, "ready")
		os.Stdout.Close()
		until := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(release); err == nil {
				break
			}
			if time.Now().After(until) {
				os.Exit(9)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Stderr.Close()
		os.WriteFile(release+".done", []byte("closed"), 0600)
		os.Exit(0)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestChromeProcessWaitChild$")
	child.Env = append(os.Environ(), "NEEXITLAG_TEST_CHROME_WAIT=hold", "GORACE=atexit_sleep_ms=0")
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		os.Exit(8)
	}
	if child.Start() != nil {
		os.Exit(8)
	}
	if _, err = bufio.NewReader(stdout).ReadString('\n'); err != nil {
		os.Exit(8)
	}
	if mode == "nonzero" {
		os.Exit(7)
	}
	os.Exit(0)
}

func TestChromeWaitSeparatesActualExitCodeFromInheritedPipeEOF(t *testing.T) {
	for _, mode := range []string{"raw-zero", "zero", "nonzero"} {
		t.Run(mode, func(t *testing.T) {
			release := filepath.Join(t.TempDir(), "release")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestChromeProcessWaitChild$")
			command.Env = append(os.Environ(), "NEEXITLAG_TEST_CHROME_WAIT="+mode, "NEEXITLAG_TEST_CHROME_RELEASE="+release, "GORACE=atexit_sleep_ms=0")
			var stderr bytes.Buffer
			command.Stderr = &stderr
			command.WaitDelay = 50 * time.Millisecond
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			var err error
			if mode == "raw-zero" {
				err = command.Wait()
			} else {
				err = waitChromeProcess(command)
			}
			// Release the orphan child deterministically, including after assertion failure.
			if e := os.WriteFile(release, []byte("release"), 0600); e != nil {
				t.Fatal(e)
			}
			until := time.Now().Add(2 * time.Second)
			for {
				if _, e := os.Stat(release + ".done"); e == nil {
					break
				}
				if time.Now().After(until) {
					t.Fatal("descendant pipe did not close")
				}
				time.Sleep(10 * time.Millisecond)
			}
			switch mode {
			case "raw-zero":
				if !errors.Is(err, exec.ErrWaitDelay) || command.ProcessState.ExitCode() != 0 {
					t.Fatal("fixture did not reproduce inherited redirected handle", err, stderr.String())
				}
			case "zero":
				if err != nil {
					t.Fatal("successful parent became networking/instrumentation failure", err)
				}
			case "nonzero":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 {
					t.Fatal("real failed process was ignored", err)
				}
			}
		})
	}
}
