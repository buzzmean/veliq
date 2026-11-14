package clientservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

func automaticTLSExchange(t *testing.T, raw net.Conn, q browserproxy.Request, roots *x509.CertPool) {
	t.Helper()
	secure := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: q.Host,
		MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	defer secure.Close()
	if err := secure.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+q.Host+"/transfer", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Close = true
	if err := request.Write(secure); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	n, err := io.Copy(io.Discard, response.Body)
	if err != nil || response.StatusCode != http.StatusOK || n != 131072 {
		t.Fatalf("status=%d transfer=%d error=%v", response.StatusCode, n, err)
	}
}

func automaticSilentSocket() net.Conn {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		_, _ = io.Copy(io.Discard, b)
	}()
	return a
}

func TestAutomaticTLSExactLocalAfterDirectSilenceAndWarmReuse(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	c.Backend = &youtubeTransformFixture{}
	c.BrowserResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, os.ErrNotExist }}
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	var mu sync.Mutex
	opened := []flowpolicy.Action{}
	open := func(ctx context.Context, request browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		mu.Lock()
		opened = append(opened, actual.Policy.Action)
		mu.Unlock()
		if actual.Destination != p.Destination || request.Host != q.Host {
			return nil, errors.New("unexpected endpoint")
		}
		switch actual.Policy.Action {
		case flowpolicy.Direct:
			return automaticSilentSocket(), nil
		case flowpolicy.DirectPlus:
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		}
		return nil, errors.New("fixture forbids RELAY when LOCAL works")
	}
	first, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, open)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	automaticTLSExchange(t, first, q, roots)
	if plan := first.(browserproxy.PlanReporter).CurrentPlan(); plan.Policy.Source != automaticTLSLocalSource {
		t.Fatalf("the route inspector lost the selected LOCAL path: %+v", plan)
	}
	if evidence := c.automaticTLSLocalPlan(cur, q, p); !evidence.confirmed {
		t.Fatal("committed transform with sustained origin data did not confirm exact scope")
	}
	other := p
	other.Destination = netip.MustParseAddrPort("74.125.111.132:443")
	if evidence := c.automaticTLSLocalPlan(cur, q, other); evidence.confirmed {
		t.Fatal("local confirmation leaked to a different IP")
	}
	otherHost := q
	otherHost.Host = "other.example.org"
	if evidence := c.automaticTLSLocalPlan(cur, otherHost, p); evidence.confirmed {
		t.Fatal("local confirmation leaked to a different authority")
	}
	stale := cur
	stale.automaticRevision += "-different"
	if evidence := c.automaticTLSLocalPlan(stale, q, p); evidence.confirmed {
		t.Fatal("local confirmation leaked across policy revisions")
	}
	second, actual, err := c.openAutomaticPlan(context.Background(), cur, q, p, open)
	if err != nil || actual.Policy.Action != flowpolicy.DirectPlus {
		t.Fatalf("warm route failed: %+v %v", actual, err)
	}
	defer second.Close()
	automaticTLSExchange(t, second, q, roots)
	mu.Lock()
	defer mu.Unlock()
	if want := []flowpolicy.Action{flowpolicy.Direct, flowpolicy.DirectPlus, flowpolicy.DirectPlus}; !reflect.DeepEqual(opened, want) {
		t.Fatalf("route sequence = %v, want %v", opened, want)
	}
	t.Log("unregistered app completed real TLS/HTTP via LOCAL after DIRECT silence and used the exact confirmed LOCAL route immediately")
}

func TestAutomaticTLSRelaysWhenLocalExhausted(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	c.BrowserResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, os.ErrNotExist }}
	server, roots := youtubeTLSHTTPFixture(t, q.Host)
	var mu sync.Mutex
	opened := []flowpolicy.Action{}
	open := func(ctx context.Context, _ browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		mu.Lock()
		opened = append(opened, actual.Policy.Action)
		mu.Unlock()
		if actual.Destination != p.Destination {
			return nil, errors.New("changed endpoint")
		}
		switch actual.Policy.Action {
		case flowpolicy.Direct, flowpolicy.DirectPlus:
			return automaticSilentSocket(), nil
		case flowpolicy.RelayRequired:
			if actual.Policy.RelayID != "VPS-01" || actual.Policy.Fallback != flowpolicy.Required {
				return nil, errors.New("relay action was not authenticated/fail-closed")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		}
		return nil, errors.New("unknown route")
	}
	raw, _, err := c.openAutomaticPlan(context.Background(), cur, q, p, open)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	automaticTLSExchange(t, raw, q, roots)
	if plan := raw.(browserproxy.PlanReporter).CurrentPlan(); plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Reason != "LOCAL_ORIGIN_SILENT" {
		t.Fatalf("terminal route or reason lost: %+v", plan)
	}
	if local := c.automaticTLSLocalPlan(cur, q, p); local.candidate != "" {
		t.Fatalf("recurring use of denied local candidate: %+v", local)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []flowpolicy.Action{flowpolicy.Direct, flowpolicy.DirectPlus, flowpolicy.RelayRequired}; !reflect.DeepEqual(opened, want) {
		t.Fatalf("route sequence = %v, want %v", opened, want)
	}
	t.Log("one DIRECT and one LOCAL first flight timed out, then the authenticated relay path carried real TLS/HTTP")
}
