package support

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const cookieName = "__Host-veliq_support"

type Server struct {
	Store   *Store
	Origin  string
	Enabled bool
	// TrustProxy is only for a loopback nginx which overwrites X-Real-IP.
	TrustProxy bool
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	fail := func(code int, reason string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
	}
	if r.Method != "GET" && r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST")
		fail(405, "method_not_allowed")
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		fail(403, "origin_denied")
		return
	}
	if r.Method == "POST" && (r.Header.Get("Origin") != s.Origin || strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json") {
		fail(403, "origin_denied")
		return
	}
	token := ""
	if c, e := r.Cookie(cookieName); e == nil {
		token = c.Value
	}
	validSession, sessionErr := s.Store.sessionStatus(ctx, token)
	if sessionErr != nil {
		fail(503, "temporarily_unavailable")
		return
	}
	if r.URL.Path == "/api/v1/support/state" && r.Method == "GET" {
		if !validSession {
			_ = json.NewEncoder(w).Encode(State{Available: s.Enabled, Messages: []Message{}})
			return
		}
		before := int64(0)
		var e error
		if v := r.URL.Query().Get("before"); v != "" {
			before, e = strconv.ParseInt(v, 10, 64)
			if e != nil || before < 0 {
				fail(400, "invalid_request")
				return
			}
		}
		ticket := r.URL.Query().Get("ticket")
		if ticket != "" && !validID(ticket) {
			fail(400, "invalid_request")
			return
		}
		st, e := s.Store.State(ctx, token, ticket, before)
		if e != nil {
			fail(503, "temporarily_unavailable")
			return
		}
		st.Available = s.Enabled
		_ = json.NewEncoder(w).Encode(st)
		return
	}
	if r.URL.Path == "/api/v1/support/forget" && r.Method == "POST" {
		if validID(token) {
			if _, e := s.Store.DB.Exec(ctx, `UPDATE support_visitors SET expires_at=now() WHERE id=$1`, hash(token)); e != nil {
				fail(503, "temporarily_unavailable")
				return
			}
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	if !s.Enabled {
		fail(503, "support_not_connected")
		return
	}
	if r.Method != "POST" {
		fail(404, "not_found")
		return
	}
	var m Mutation
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if e := d.Decode(&m); e != nil {
		fail(400, "invalid_request")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(400, "invalid_request")
		return
	}
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.TrustProxy {
		if ip := net.ParseIP(peer); ip != nil && ip.IsLoopback() {
			if ip = net.ParseIP(r.Header.Get("X-Real-IP")); ip != nil {
				peer = ip.String()
			}
		}
	}
	if r.URL.Path == "/api/v1/support/session" {
		if !validSession {
			var e error
			token, e = s.Store.Session(ctx, peer)
			if e != nil {
				if errors.Is(e, ErrLimit) {
					fail(429, "rate_limited")
				} else {
					fail(503, "temporarily_unavailable")
				}
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", MaxAge: 30 * 86400, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	action := ""
	switch r.URL.Path {
	case "/api/v1/support/message":
		action = "message"
	case "/api/v1/support/resolve":
		action = "resolve"
	default:
		fail(404, "not_found")
		return
	}
	if !validSession {
		fail(401, "session_expired")
		return
	}
	id, e := s.Store.Mutate(ctx, token, peer, action, m)
	if e != nil {
		switch {
		case errors.Is(e, ErrConflict):
			fail(409, "ticket_changed")
		case errors.Is(e, ErrUnauthorized):
			fail(401, "session_expired")
		case errors.Is(e, ErrInvalid):
			fail(400, "invalid_request")
		case errors.Is(e, ErrLimit):
			w.Header().Set("Retry-After", "60")
			fail(429, "rate_limited")
		default:
			fail(503, "temporarily_unavailable")
		}
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"ticket": id})
}
