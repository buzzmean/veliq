package browserproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestHTTP80UpgradeProbe(t *testing.T) {
	for _, tc := range []struct {
		name, reply   string
		witness, want bool
	}{
		{"upgrade", "HTTP/1.1 301 Moved\r\nLocation: https://www.example.org/\r\n\r\n", true, true},
		{"no-witness", "HTTP/1.1 301 Moved\r\nLocation: https://www.example.org/\r\n\r\n", false, false},
		{"block-page", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, false},
		{"foreign", "HTTP/1.1 302 Found\r\nLocation: https://other.example.org/\r\n\r\n", true, false},
		{"userinfo", "HTTP/1.1 302 Found\r\nLocation: https://user@www.example.org/\r\n\r\n", true, false},
		{"query", "HTTP/1.1 302 Found\r\nLocation: https://www.example.org/?token=value\r\n\r\n", true, false},
		{"duplicate", "HTTP/1.1 301 Moved\r\nLocation: https://www.example.org/\r\nLocation: https://other.example.org/\r\n\r\n", true, false},
		{"limit", "HTTP/1.1 301 Moved\r\nX-Padding: " + strings.Repeat("x", 9000) + "\r\nLocation: https://www.example.org/\r\n\r\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					t.Error(err)
					return
				}
				if req.Method != "HEAD" || req.Host != "www.example.org" || req.URL.RequestURI() != "/" || req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" {
					t.Error("probe included browser context")
				}
				io.WriteString(server, tc.reply)
			}()
			opens := 0
			_, reason := ProbeHTTP80Upgrade(context.Background(), "www.example.org", func(context.Context) (net.Conn, error) { opens++; return client, nil }, func() bool { return tc.witness })
			<-done
			if (reason == "HTTP80_HTTPS_UPGRADE_OBSERVED") != tc.want || opens != 1 {
				t.Fatal(reason, opens)
			}
		})
	}
}
