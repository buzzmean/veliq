package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCodeClientNeverFollowsCredentialRedirectOrReflectsServerErrors(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true); w.WriteHeader(500) }))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	code, _ := NewCode()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	q, _ := NewRequest(strings.Repeat("a", 32), strings.Repeat("b", 64), key)
	_, e := (Client{URL: server.URL, HTTP: server.Client()}).Enroll(context.Background(), code, q, x509.NewCertPool())
	if e == nil || leaked.Load() || strings.Contains(e.Error(), code) {
		t.Fatal("redirect/credential disclosure")
	}
}
