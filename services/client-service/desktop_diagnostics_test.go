package clientservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiagnosticsUsesConfiguredControlPlaneTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	c := New(context.Background())
	defer c.Close()
	c.ControlPlaneURL = server.URL
	c.DiagnosticHTTPClient = server.Client()
	for _, check := range c.Diagnostics(context.Background()) {
		if check.Name == "Control Plane" {
			if check.Status != "healthy" {
				t.Fatalf("private-CA health failed: %s", check.Status)
			}
			return
		}
	}
	t.Fatal("control-plane check missing")
}
