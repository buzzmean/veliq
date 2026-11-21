package webprobe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProofNeverTransmitsSecretAndRejectsTampering(t *testing.T) {
	token := "private-test-key-1234567890123456"
	nonce := "0123456789abcdef"
	signature := SignRequest(token, "GET", "/observe", nonce)
	if strings.Contains(signature, token) {
		t.Fatal("secret transmitted")
	}
	request := httptest.NewRequest("GET", "http://target/observe?nonce="+nonce, nil)
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("X-Neexitlag-Proof", signature)
	response := httptest.NewRecorder()
	Handler(token).ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	o, e := ReadObservation(response.Body)
	if e != nil || !VerifyObservation(token, o) {
		t.Fatal(o, e)
	}
	o.Source = "203.0.113.1"
	if VerifyObservation(token, o) {
		t.Fatal("forged source accepted")
	}
	request.Header.Set("X-Neexitlag-Proof", SignRequest(token, "GET", "/ws", nonce))
	response = httptest.NewRecorder()
	Handler(token).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("path substitution accepted")
	}
}
