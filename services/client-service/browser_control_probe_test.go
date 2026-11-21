package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func publicFixtureOpen(addr string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", addr) }
}
func TestPublicGatewayUsesVerifiedTLSAndRealNoncePongs(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprint(wrong), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("probe sent credentials")
				}
				conn, rw, e := w.(http.Hijacker).Hijack()
				if e != nil {
					return
				}
				defer conn.Close()
				sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
				body := []byte(`{"op":10,"d":{"heartbeat_interval":45000}}`)
				rw.WriteByte(0x81)
				rw.WriteByte(byte(len(body)))
				rw.Write(body)
				rw.Flush()
				for i := 0; i < 3; i++ {
					nonce, e := readFixturePing(rw.Reader)
					if e != nil {
						return
					}
					if wrong {
						nonce[0] ^= 1
					}
					rw.WriteByte(0x8a)
					rw.WriteByte(byte(len(nonce)))
					rw.Write(nonce)
					if e = rw.Flush(); e != nil {
						return
					}
				}
			})
			server, roots := youtubeTLSHTTPFixture(t, "gateway.discord.gg", handler)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			p := probePublicService(ctx, "gateway.discord.gg", roots, publicFixtureOpen(server.Listener.Addr().String()))
			if wrong {
				if localProbeSuccess("gateway.discord.gg", p) {
					t.Fatal("wrong nonce accepted")
				}
				return
			}
			if !localProbeSuccess("gateway.discord.gg", p) || p.Bytes == 0 || p.BodyBytes >= 64*1024 {
				t.Fatal("control proof invented bulk transfer", p)
			}
			if localProbeSuccess("ordinary.example", p) || localProbeOutcome(p, false) != "NO_TRANSFORM" {
				t.Fatal("control success escaped scope/transform requirement")
			}
		})
	}
}
func readFixturePing(r *bufio.Reader) ([]byte, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	if h[0] != 0x89 || h[1]&0x80 == 0 || h[1]&127 > 125 {
		return nil, fmt.Errorf("not a masked ping")
	}
	mask := make([]byte, 4)
	if _, e := io.ReadFull(r, mask); e != nil {
		return nil, e
	}
	p := make([]byte, h[1]&127)
	_, e := io.ReadFull(r, p)
	for i := range p {
		p[i] ^= mask[i%4]
	}
	return p, e
}
func TestPublicDiscordAssetBatchCrosses64KBOnOneTLSConnection(t *testing.T) {
	var requests, opens atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "image/png")
		w.Write(append([]byte{137, 'P', 'N', 'G', 13, 10, 26, 10}, bytes.Repeat([]byte{1}, 1300)...))
	})
	server, roots := youtubeTLSHTTPFixture(t, "cdn.discordapp.com", handler)
	open := func(ctx context.Context) (net.Conn, error) {
		opens.Add(1)
		return publicFixtureOpen(server.Listener.Addr().String())(ctx)
	}
	p := probePublicService(context.Background(), "cdn.discordapp.com", roots, open)
	if !localProbeSuccess("cdn.discordapp.com", p) || p.BodyBytes <= 64*1024 || opens.Load() != 1 || requests.Load() < 49 {
		t.Fatal("batch did not measure sustained same-connection bytes", p, opens.Load(), requests.Load())
	}
}
func TestPublicRedirectIsNotGeneralBulkOrUnverifiedTLSSuccess(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://discord.com/", http.StatusFound)
	})
	server, roots := youtubeTLSHTTPFixture(t, "discord.gg", handler)
	open := publicFixtureOpen(server.Listener.Addr().String())
	p := probePublicService(context.Background(), "discord.gg", roots, open)
	if !localProbeSuccess("discord.gg", p) || localProbeSuccess("www.youtube.com", p) {
		t.Fatal("redirect proof escaped exact service scope", p)
	}
	p = probePublicService(context.Background(), "discord.gg", nil, open)
	if p.Failure != "TLS_CERTIFICATE_ERROR" || localProbeSuccess("discord.gg", p) {
		t.Fatal("certificate verification bypassed", p)
	}
}

func TestPublicYouTubeRedirectIsScopedAndNeverBulkProof(t *testing.T) {
	server, roots := youtubeTLSHTTPFixture(t, "youtube.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://www.youtube.com/")
		w.WriteHeader(301)
	}))
	p := probePublicService(context.Background(), "youtube.com", roots, publicFixtureOpen(server.Listener.Addr().String()))
	if !localProbeSuccess("youtube.com", p) || localProbeSuccess("www.youtube.com", p) || youtubeTransferOK(p) {
		t.Fatal(p)
	}
}
