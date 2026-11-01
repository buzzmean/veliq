package browserproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProbeHTTP80Upgrade sends a standalone, credential-free HEAD. A same-host
// HTTPS upgrade is HTTP reachability evidence only, never authenticated TLS,
// page/body success or permission to replay a browser request.
func ProbeHTTP80Upgrade(ctx context.Context, host string, open func(context.Context) (net.Conn, error), committed func() bool) (status int, reason string) {
	if !ValidPublicDNSName(host) {
		return 0, "HTTP80_HOST_INVALID"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := open(ctx)
	if err != nil {
		return 0, "HTTP80_OPEN_FAILED"
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return 0, "HTTP80_DEADLINE_FAILED"
	}
	req := &http.Request{Method: "HEAD", URL: &url.URL{Path: "/"}, Host: host, Header: http.Header{"Connection": {"close"}, "User-Agent": {"VELIQ HTTP80 probe"}}, Close: true}
	if req.Write(conn) != nil {
		return 0, "HTTP80_WRITE_FAILED"
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 8192)), req)
	if err != nil {
		return 0, "HTTP80_HEADER_FAILED"
	}
	defer response.Body.Close()
	status = response.StatusCode
	if status != 301 && status != 302 && status != 307 && status != 308 || len(response.Header.Values("Location")) != 1 {
		return status, "HTTP80_UPGRADE_NOT_OBSERVED"
	}
	target, err := url.Parse(response.Header.Get("Location"))
	if err != nil || target.Scheme != "https" || target.User != nil || !strings.EqualFold(target.Hostname(), host) || target.Port() != "" && target.Port() != "443" || target.Opaque != "" || target.RawQuery != "" || target.Fragment != "" || target.EscapedPath() != "" && target.EscapedPath() != "/" {
		return status, "HTTP80_UPGRADE_NOT_OBSERVED"
	}
	// Inspect the exact socket witness while the connection is still open.
	if committed == nil || !committed() {
		return status, "HTTP80_TRANSFORM_NOT_COMMITTED"
	}
	return status, "HTTP80_HTTPS_UPGRADE_OBSERVED"
}
