// Package webprobe supplies controlled HTTP/TLS/WebSocket acceptance endpoints.
// It is a destination server, never a TLS interception proxy.
package webprobe

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Observation struct {
	Source   string `json:"source"`
	Nonce    string `json:"nonce"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
	Proof    string `json:"proof"`
}

func Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if len(token) < 24 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Neexitlag-Proof")), []byte(SignRequest(token, r.Method, r.URL.Path, nonce))) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if len(nonce) < 16 || len(nonce) > 128 {
			http.Error(w, "invalid nonce", 400)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "peer unavailable", 500)
			return
		}
		o := Observation{Source: host, Nonce: nonce, Protocol: r.Proto, TLS: r.TLS != nil}
		o.Proof = signObservation(token, o)
		if r.URL.Path == "/ws" {
			if r.ProtoMajor != 1 || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || r.Header.Get("Sec-WebSocket-Version") != "13" {
				http.Error(w, "WebSocket upgrade required", 400)
				return
			}
			key, e := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
			if e != nil || len(key) != 16 {
				http.Error(w, "invalid key", 400)
				return
			}
			h, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "upgrade unavailable", 400)
				return
			}
			c, rw, e := h.Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
			if rw.Flush() != nil {
				return
			}
			// One small RFC6455 text frame then close; TLS stays end-to-end.
			payload, _ := json.Marshal(o)
			if len(payload) > 65535 {
				return
			}
			header := []byte{0x81, 126, byte(len(payload) >> 8), byte(len(payload))}
			_, _ = c.Write(append(header, payload...))
			_, _ = c.Write([]byte{0x88, 0})
			return
		}
		if r.URL.Path != "/observe" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(o)
	})
}
func ReadObservation(r io.Reader) (Observation, error) {
	var o Observation
	err := json.NewDecoder(io.LimitReader(r, 4096)).Decode(&o)
	return o, err
}

// Secrets are never transmitted, even in the deliberate plaintext HTTP test.
func digest(token, message string) string {
	h := hmac.New(sha256.New, []byte(token))
	_, _ = h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
func SignRequest(token, method, path, nonce string) string {
	return digest(token, "request\n"+method+"\n"+path+"\n"+nonce)
}
func signObservation(token string, o Observation) string {
	return digest(token, fmt.Sprintf("response\n%s\n%s\n%s\n%t", o.Nonce, o.Source, o.Protocol, o.TLS))
}
func VerifyObservation(token string, o Observation) bool {
	return subtle.ConstantTimeCompare([]byte(o.Proof), []byte(signObservation(token, o))) == 1
}
