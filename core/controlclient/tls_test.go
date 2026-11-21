package controlclient

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitPrivateTLSCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	client, e := HTTPSClient(path)
	if e != nil {
		t.Fatal(e)
	}
	res, e := client.Get(server.URL)
	if e != nil {
		t.Fatal("private CA rejected", e)
	}
	res.Body.Close()
	if _, e = http.DefaultClient.Get(server.URL); e == nil {
		t.Fatal("test server unexpectedly trusted without explicit CA")
	}
	os.WriteFile(path, []byte("not a certificate"), 0600)
	if _, e = HTTPSClient(path); e == nil {
		t.Fatal("malformed CA accepted")
	}
}
