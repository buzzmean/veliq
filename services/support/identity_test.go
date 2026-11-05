package support

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type verifierFunc func(context.Context, string) (string, error)

func (f verifierFunc) Verify(ctx context.Context, token string) (string, error) { return f(ctx, token) }

func TestAccountIsolationAndRevocation(t *testing.T) {
	s := testStore(t)
	revoked := false
	h := &Server{Store: s, Origin: "https://veliq.test", Enabled: true, Accounts: verifierFunc(func(_ context.Context, token string) (string, error) {
		switch token {
		case "A":
			if !revoked {
				return strings.Repeat("a", 32), nil
			}
		case "B":
			return strings.Repeat("b", 32), nil
		case "down":
			return "", errors.New("unavailable")
		}
		return "", ErrUnauthorized
	})}
	call := func(method, path, account, guest, scope, body string) (*httptest.ResponseRecorder, State) {
		r := httptest.NewRequest(method, h.Origin+apiPrefix+path, strings.NewReader(body))
		r.Header.Set("Origin", h.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Support-Context", scope)
		// Neither of these client claims may grant account A access.
		r.Header.Set("X-Account-Email", "a@example.test")
		r.Header.Set("X-Support-Owner", "a@example.test")
		if account != "" {
			r.AddCookie(&http.Cookie{Name: accountCookie, Value: account})
		}
		if guest != "" {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: guest})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var st State
		_ = json.Unmarshal(w.Body.Bytes(), &st)
		return w, st
	}
	guest := visitor(t, s)
	guestTicket := newTicket(t, s, guest)
	w, a := call("GET", "state", "A", guest, "", "")
	if w.Code != 200 || a.Ticket != nil || a.Identity != "account" {
		t.Fatal("guest was claimed", w.Code)
	}
	if s.ValidSession(context.Background(), guest) {
		t.Fatal("guest access was not detached")
	}
	w, _ = call("POST", "message", "A", "", a.Context, `{"key":"`+randomID()+`","body":"private A"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	_, a = call("GET", "state", "A", "", "", "")
	if a.Ticket == nil {
		t.Fatal("no account ticket")
	}
	_, b := call("GET", "state?ticket="+a.Ticket.ID, "B", "", "", "")
	if b.Ticket != nil || len(b.Messages) != 0 {
		t.Fatal("account B read account A")
	}
	for _, action := range []string{"message", "resolve"} {
		w, _ = call("POST", action, "B", "", b.Context, `{"key":"`+randomID()+`","ticket":"`+a.Ticket.ID+`","body":"stolen","revision":1}`)
		if w.Code != 401 {
			t.Fatal("cross account mutation", action, w.Code)
		}
	}
	w, _ = call("POST", "message", "B", "", a.Context, `{"key":"`+randomID()+`","body":"stale draft"}`)
	if w.Code != 409 {
		t.Fatal("old tab draft sent to new account", w.Code)
	}
	// Even a guessed deterministic account namespace is not a guest credential.
	forged := hash("verified-account\x00" + strings.Repeat("a", 32))
	w, st := call("GET", "state", "", forged, "", "")
	if w.Code != 200 || st.Session || st.Ticket != nil {
		t.Fatal("guest impersonation")
	}
	revoked = true
	for _, account := range []string{"A", "down"} {
		w, st = call("GET", "state", account, guest, "", "")
		if (w.Code != 401 && w.Code != 503) || st.Ticket != nil {
			t.Fatal("account failure downgraded to guest")
		}
	}
	revoked = false
	_, again := call("GET", "state", "A", "", "", "")
	if again.Ticket == nil || again.Ticket.ID != a.Ticket.ID {
		t.Fatal("account history lost after reauthentication")
	}
	var retained bool
	if e := s.DB.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM support_tickets WHERE id=$1)`, guestTicket).Scan(&retained); e != nil || !retained {
		t.Fatal("guest ticket deleted")
	}
}

func TestLegacyMigrationPreservesTicketsButRevokesAccess(t *testing.T) {
	s := testStore(t)
	token := visitor(t, s)
	ticket := newTicket(t, s, token)
	if _, e := s.DB.Exec(context.Background(), `UPDATE support_visitors SET owner_kind='legacy' WHERE id=$1`, hash(token)); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s.ValidSession(context.Background(), token) {
		t.Fatal("legacy token still authorized")
	}
	var id string
	if e := s.DB.QueryRow(context.Background(), `SELECT id FROM support_tickets WHERE id=$1`, ticket).Scan(&id); e != nil {
		t.Fatal("ticket lost", e)
	}
	h := &Server{Store: s, Origin: "https://veliq.test", Enabled: true}
	r := httptest.NewRequest("GET", "https://veliq.test/api/v1/support/state", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-veliq_support", Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 410 {
		t.Fatal("old route alive")
	}
}

func TestAccountVerifierTLSAndFailureBoundaries(t *testing.T) {
	status := 200
	body := `{"account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/account" || r.Method != "GET" || len(r.Cookies()) != 1 || r.Cookies()[0].Name != accountCookie {
			t.Error("unexpected upstream request")
		}
		if status == 302 {
			w.Header().Set("Location", "https://attacker.invalid/")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	v, e := NewAccountVerifier(srv.URL+"/api/v1/account", "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.Verify(context.Background(), strings.Repeat("a", 43)); e == nil {
		t.Fatal("untrusted TLS accepted")
	}
	v.Client = srv.Client()
	v.Client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if email, e := v.Verify(context.Background(), strings.Repeat("a", 43)); e != nil || email != strings.Repeat("a", 32) {
		t.Fatal(email, e)
	}
	for _, code := range []int{401, 403, 500, 302} {
		status = code
		if _, e = v.Verify(context.Background(), strings.Repeat("a", 43)); e == nil {
			t.Fatal("upstream failure accepted", code)
		}
	}
	status = 200
	for _, bad := range []string{`{}`, `{"account_id":"fake"}`, `{"account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {}`, `{"account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","padding":"` + strings.Repeat("x", 1<<20) + `"}`} {
		body = bad
		if _, e = v.Verify(context.Background(), strings.Repeat("a", 43)); e == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	for _, endpoint := range []string{"http://veliq.test/api/v1/account", "https://veliq.test/admin", "https://user:pass@veliq.test/api/v1/account", "https://veliq.test/api/v1/account?url=bad"} {
		if _, e = NewAccountVerifier(endpoint, ""); e == nil {
			t.Fatal("unsafe upstream accepted")
		}
	}
}
