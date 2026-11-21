package flowpolicy

import (
	"fmt"
	"testing"
	"time"
)

func TestBrowserLearningRealResultsBoundedOriginIsolation(t *testing.T) {
	now := time.Now()
	b := NewBrowserLearning()
	k := LearnKey{Network: "isp", Application: "chrome.exe", Protocol: "tcp", Target: "blocked.example", Port: 443, Revision: "r1"}
	a, err := b.Begin(k, "split1", "VPS-01", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Route.Action != Direct || a.Confirmed {
		t.Fatal(a)
	}
	if _, err = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, ResponseBytes: 1}, "split1", "VPS-01", now); err == nil {
		t.Fatal("ACK alone accepted")
	}
	if _, err = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: false, HTTPStatus: 200, ResponseBytes: 200}, "split1", "VPS-01", now); err == nil {
		t.Fatal("uncorrelated HTTP accepted")
	}
	old := a.Token
	a, err = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "split1", "VPS-01", now)
	if err != nil || a.Route.Action != DirectPlus {
		t.Fatal(a, err)
	}
	if _, err = b.Observe(k, BrowserObservation{Token: old, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "split1", "VPS-01", now); err == nil {
		t.Fatal("late old flow advanced current attempt")
	}
	other := k
	other.Target = "ordinary.example"
	o, _ := b.Begin(other, "split1", "VPS-01", now)
	if o.Route.Action != Direct {
		t.Fatal("cross-domain inheritance", o)
	}
	other = k
	other.Network = "another-isp"
	if _, ok := b.Lookup(other, now); ok {
		t.Fatal("cross-network inheritance")
	}
	a, err = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "CONNECTION_RESET"}, "split1", "VPS-01", now)
	if err != nil || a.Route.Action != RelayRequired || a.Route.Fallback != Required {
		t.Fatal(a, err)
	}
	a, err = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, HTTPStatus: 200, ResponseBytes: 100}, "split1", "VPS-01", now)
	if err != nil || !a.Confirmed || a.Outcome != "HTTP_SUCCESS" || a.HTTPStatus != 200 {
		t.Fatal(a, err)
	}
	if _, ok := b.Lookup(k, now.Add(16*time.Minute)); ok {
		t.Fatal("cache never expires")
	}
}
func TestBrowserApplicationErrorIsNotPassOrEgressRetry(t *testing.T) {
	now := time.Now()
	b := NewBrowserLearning()
	k := LearnKey{Network: "n", Application: "chrome.exe", Protocol: "tcp", Target: "auth.example", Port: 443}
	a, _ := b.Begin(k, "split1", "VPS-01", now)
	a, err := b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, HTTPStatus: 403, ResponseBytes: 200}, "split1", "VPS-01", now)
	if err != nil || a.Confirmed || a.Stage != 0 || a.Outcome != "HTTP_APPLICATION_ERROR" {
		t.Fatal(a, err)
	}
	if _, err = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "split1", "VPS-01", now); err == nil {
		t.Fatal("cooldown ignored")
	}
}
func TestBrowserLearningCapacityAndRelayFailureNoDirectFallback(t *testing.T) {
	now := time.Now()
	b := NewBrowserLearning()
	k := LearnKey{Network: "n", Application: "chrome.exe", Protocol: "tcp", Target: "a.example", Port: 443}
	a, _ := b.Begin(k, "", "VPS-01", now)
	a, _ = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "", "VPS-01", now)
	a, _ = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "", "VPS-01", now)
	if a.Route.Action != RelayRequired || a.Stage != 2 || a.RetryAfter.IsZero() {
		t.Fatal(a)
	}
	for i := 0; i < 511; i++ {
		k.Target = fmt.Sprintf("d%d.example", i)
		if _, err := b.Begin(k, "", "VPS-01", now); err != nil {
			t.Fatal(err)
		}
	}
	k.Target = "overflow.example"
	if _, err := b.Begin(k, "", "VPS-01", now); err == nil {
		t.Fatal("unbounded cache")
	}
}

func TestBrowserCertificateFailureNeverChangesEgress(t *testing.T) {
	now := time.Now()
	b := NewBrowserLearning()
	k := LearnKey{Network: "n", Application: "chrome.exe", Protocol: "tcp", Target: "cert.example", Port: 443}
	a, _ := b.Begin(k, "disorder", "VPS-01", now)
	a, err := b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "TLS_CERTIFICATE_ERROR"}, "disorder", "VPS-01", now)
	if err != nil || a.Confirmed || a.Route.Action != Direct || a.RetryAfter.IsZero() || a.Outcome != "TLS_CERTIFICATE_ERROR" {
		t.Fatal(a, err)
	}
}

func TestBrowserLearnedAddressIsScopedAndInvalidated(t *testing.T) {
	b := NewBrowserLearning()
	now := time.Now()
	k := LearnKey{Network: "isp", Application: "chrome", Protocol: "tcp", Target: "web.telegram.org", Port: 443}
	a, _ := b.Begin(k, "", "VPS-01", now)
	a, _ = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "", "VPS-01", now)
	a, err := b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, HTTPStatus: 200, ResponseBytes: 100, Destination: "203.0.113.2:443"}, "", "VPS-01", now)
	if err != nil || !a.Confirmed || a.Destination != "203.0.113.2:443" || a.Route.Action != RelayRequired {
		t.Fatal(a, err)
	}
	other := k
	other.Target = "ordinary.example"
	if _, ok := b.Lookup(other, now); ok {
		t.Fatal("cross-origin cache")
	}
	b.Forget(k)
	a, _ = b.Begin(k, "", "VPS-01", now)
	if a.Confirmed || a.Destination != "" || a.Route.Action != Direct {
		t.Fatal("stale DNS route reused", a)
	}
}

func TestBrowserTLSProbeFailureOffersUnverifiedRelayNotKnownFailedDirect(t *testing.T) {
	now := time.Now()
	b := NewBrowserLearning()
	k := LearnKey{Network: "isp", Application: "chrome", Protocol: "tcp", Target: "web.telegram.org", Port: 443}
	a, _ := b.Begin(k, "", "VPS-01", now)
	a, _ = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "", "VPS-01", now)
	a, err := b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "TLS_FAILED", OriginTLS: true, Destination: "203.0.113.1:443"}, "", "VPS-01", now)
	if err != nil || a.Confirmed || !a.BrowserTrial || a.Route.Action != RelayRequired || a.Route.Fallback != Required || a.Outcome != "ORIGIN_TLS_BROWSER_TRIAL_UNVERIFIED" {
		t.Fatal(a, err)
	}
	if a.RetryAfter.Sub(now) > 5*time.Second {
		t.Fatal("long false healthy cache", a)
	}
	if _, ok := b.Lookup(k, now.Add(6*time.Second)); ok {
		t.Fatal("unverified browser trial persisted")
	}
	// Failed relay OPEN is categorically different: it must not pretend Chrome
	// can use a transport that never opened.
	a, _ = b.Begin(k, "", "VPS-01", now)
	a, _ = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "NETWORK_TIMEOUT"}, "", "VPS-01", now)
	a, _ = b.Observe(k, BrowserObservation{Token: a.Token, Correlated: true, NetworkError: "CONNECTION_FAILED"}, "", "VPS-01", now)
	if a.BrowserTrial || a.Confirmed {
		t.Fatal(a)
	}
}
