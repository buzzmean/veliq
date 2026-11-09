package clientservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

func automaticOpenFailure(cause error) error {
	return fmt.Errorf("open destination: %w", &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: cause}})
}

func TestDirectOpenFailureClassificationUsesCauseNotNetErrorInterface(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"permission", automaticOpenFailure(syscall.EACCES), false},
		{"operation-not-permitted", automaticOpenFailure(syscall.EPERM), false},
		{"process-socket-limit", automaticOpenFailure(syscall.EMFILE), false},
		{"system-socket-limit", automaticOpenFailure(syscall.ENFILE), false},
		{"local-address-unavailable", automaticOpenFailure(syscall.EADDRNOTAVAIL), false},
		{"unknown-errno", automaticOpenFailure(syscall.Errno(999999)), false},
		{"unknown-net-op-error", automaticOpenFailure(errors.New("local opener failed")), false},
		{"dns-timeout", &net.DNSError{Err: "timeout", Name: "example.invalid", IsTimeout: true}, false},
		{"cancelled", automaticOpenFailure(context.Canceled), false},
		{"cancelled-and-timeout", errors.Join(context.Canceled, context.DeadlineExceeded), false},
		{"deadline", automaticOpenFailure(context.DeadlineExceeded), true},
		{"io-deadline", automaticOpenFailure(os.ErrDeadlineExceeded), true},
		{"timed-out", automaticOpenFailure(syscall.ETIMEDOUT), true},
		{"refused", automaticOpenFailure(syscall.ECONNREFUSED), true},
		{"reset", automaticOpenFailure(syscall.ECONNRESET), true},
		{"host-unreachable", automaticOpenFailure(syscall.EHOSTUNREACH), true},
		{"network-unreachable", automaticOpenFailure(syscall.ENETUNREACH), true},
		{"winsock-permission", automaticOpenFailure(syscall.Errno(10013)), false},
		{"winsock-socket-limit", automaticOpenFailure(syscall.Errno(10024)), false},
		{"winsock-local-address", automaticOpenFailure(syscall.Errno(10049)), false},
		{"winsock-timeout", automaticOpenFailure(syscall.Errno(10060)), runtime.GOOS == "windows"},
		{"winsock-refused", automaticOpenFailure(syscall.Errno(10061)), runtime.GOOS == "windows"},
		{"winsock-reset", automaticOpenFailure(syscall.Errno(10054)), runtime.GOOS == "windows"},
		{"winsock-host-unreachable", automaticOpenFailure(syscall.Errno(10065)), runtime.GOOS == "windows"},
		{"winsock-network-unreachable", automaticOpenFailure(syscall.Errno(10051)), runtime.GOOS == "windows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryableDirectOpen(tc.err); got != tc.want {
				t.Fatalf("retryableDirectOpen(%v)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestAutomaticLocalOpenFailuresNeitherRetryNorPoisonDestination(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, cause := range []error{syscall.EACCES, syscall.EMFILE, syscall.EADDRNOTAVAIL, errors.New("AUTOMATIC_SCOPE_CHANGED"), context.Canceled, syscall.Errno(10013), syscall.Errno(10024), syscall.Errno(10049)} {
			t.Run(fmt.Sprintf("tls=%v/%v", secure, cause), func(t *testing.T) {
				c, cur, q, p := automaticFixture(t)
				if !secure {
					q.Host, q.Port, q.Secure = "", 5222, false
					p.Destination = netip.AddrPortFrom(p.Destination.Addr(), q.Port)
				}
				opens := 0
				failure := automaticOpenFailure(cause)
				conn, actual, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
					opens++
					if plan.Policy.Action != flowpolicy.Direct {
						t.Errorf("local failure caused %s retry", plan.Policy.Action)
					}
					return nil, failure
				})
				if conn != nil || !errors.Is(err, cause) || opens != 1 || actual.Policy.Action != flowpolicy.Direct {
					t.Fatalf("conn=%v err=%v opens=%d action=%s", conn, err, opens, actual.Policy.Action)
				}
				key := c.directTimeoutKey(cur, q, p)
				if !secure {
					key.Host = p.Destination.Addr().String()
				}
				if c.browser.directTimeouts.AddressFailed(key, time.Now()) || c.browser.directTimeouts.Stats().ActiveAddresses != 0 || c.browser.directTimeouts.Stats().ActiveOrigins != 0 {
					t.Fatal("local failure poisoned network/application/destination learning")
				}
			})
		}
	}
}

func TestAutomaticNetworkOpenFailuresRetainBoundedRelayRecovery(t *testing.T) {
	for _, cause := range []error{context.DeadlineExceeded, syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH} {
		t.Run(cause.Error(), func(t *testing.T) {
			c, cur, q, p := automaticFixture(t)
			q.Host, q.Port, q.Secure = "", 5222, false
			p.Destination = netip.AddrPortFrom(p.Destination.Addr(), q.Port)
			direct, relay := 0, 0
			left, right := net.Pipe()
			defer right.Close()
			conn, actual, err := c.openAutomaticPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
				if plan.Policy.Action == flowpolicy.Direct {
					direct++
					return nil, automaticOpenFailure(cause)
				}
				relay++
				return left, nil
			})
			defer left.Close()
			if err != nil || conn != left || direct != 1 || relay != 1 || actual.Policy.Action != flowpolicy.RelayRequired || actual.Policy.Fallback != flowpolicy.Required {
				t.Fatalf("conn=%v err=%v direct=%d relay=%d plan=%+v", conn, err, direct, relay, actual)
			}
			key := c.directTimeoutKey(cur, q, p)
			key.Host = p.Destination.Addr().String()
			if !c.browser.directTimeouts.AddressFailed(key, time.Now()) || c.browser.directTimeouts.AddressFailed(key, time.Now().Add(11*time.Minute)) {
				t.Fatal("actual failure must have an expiring destination-scoped verdict")
			}
		})
	}
}
