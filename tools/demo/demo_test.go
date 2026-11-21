package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/ipc"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestRealDemoHTTPMeasurementsAndFailover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	lab, e := New(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lab.Close()
	server := httptest.NewUnstartedServer(nil)
	address := server.Listener.Addr().String()
	server.Config.Handler = lab.Handler(address)
	server.Start()
	defer server.Close()
	u, _ := url.Parse(server.URL)
	call := func(method string, payload any, token string) ipc.Response {
		t.Helper()
		id, _ := security.NewID()
		raw, _ := json.Marshal(payload)
		q := ipc.Request{Version: 1, ID: id, SentAt: time.Now(), Token: token, Method: method, Payload: raw}
		b, _ := json.Marshal(q)
		request, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/ipc", bytes.NewReader(b))
		request.Host = u.Host
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		response, e := http.DefaultClient.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		var reply ipc.Response
		if e = json.NewDecoder(response.Body).Decode(&reply); e != nil {
			t.Fatal(e)
		}
		return reply
	}
	if reply := call("status", nil, "wrong"); reply.OK || reply.Code != "unauthorized" {
		t.Fatal("anonymous command accepted")
	}
	if reply := call("status", nil, lab.Token); !reply.OK {
		t.Fatal(reply.Error)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	primary := ""
	for primary == "" {
		select {
		case <-ctx.Done():
			t.Fatal("route selection timed out")
		case <-ticker.C:
			s := lab.Controller.Snapshot()
			if s.Primary != optimizer.Direct && s.RXBytes > 0 && len(s.Routes) == 4 {
				primary = s.Primary
			}
		}
	}
	if reply := call("demo.fail-relay", map[string]string{"id": primary}, lab.Token); !reply.OK {
		t.Fatal(reply.Error)
	}
	for {
		select {
		case <-ctx.Done():
			t.Fatal("real relay failure did not select backup")
		case <-ticker.C:
			s := lab.Controller.Snapshot()
			if s.Primary != primary && s.Primary != "" {
				if reply := call("diagnostics", nil, lab.Token); !reply.OK {
					t.Fatal(reply.Error)
				}
				t.Logf("real route selection %s -> %s, rx=%d", primary, s.Primary, s.RXBytes)
				return
			}
		}
	}
}
