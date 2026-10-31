package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/locallearning"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/security"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestPostgresLearningDeviceProofBindingReplayRevocationAndNoSchemaChange(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := s.DB.Exec(ctx, "INSERT INTO users(id,name) VALUES('learning-user','fixture')"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(ctx, "INSERT INTO devices(id,user_id,name,public_key) VALUES('learning-device','learning-user','fixture',$1)", base64.RawURLEncoding.EncodeToString(pub)); e != nil {
		t.Fatal(e)
	}
	a := &API{Store: s, Settings: Settings{KeyID: "test", SigningKey: signer, LocalLearningFile: filepath.Join(t.TempDir(), "learning.json")}}
	command := locallearning.Command{Scope: locallearning.Scope{Group: "googlevideo:sn-abc"}, Action: "observe"}
	makeRequest := func(c locallearning.Command) locallearning.Request {
		p, e := security.NewProof("learning-device", locallearning.Audience(c), key, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		return locallearning.Request{Command: c, Proof: p}
	}
	call := func(q locallearning.Request) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(q)
		r := httptest.NewRequest("POST", "/api/v1/local/learning", bytes.NewReader(raw))
		r.RemoteAddr = "198.51.100.45:12345"
		r.Header.Set("X-Forwarded-For", "192.168.1.3")
		w := httptest.NewRecorder()
		a.localLearning(w, r)
		return w
	}
	q := makeRequest(command)
	w := call(q)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	doc, e := locallearning.Validate(map[string]ed25519.PublicKey{"test": signer.Public().(ed25519.PublicKey)}, w.Body.Bytes(), command.Scope, time.Now())
	if e != nil || !doc.Picker {
		t.Fatal(doc, e)
	}
	if w = call(q); w.Code != 401 {
		t.Fatal("proof replay accepted", w.Code)
	}
	q.Command.Action = "report"
	if w = call(q); w.Code != 400 {
		t.Fatal("unsigned action accepted", w.Code)
	}
	plans, _ := localstrategy.BundledCatalog().Compile()
	command.Action = "report"
	command.Candidate = plans[0].ID
	command.Applied = true
	command.BodyBytes = 100000
	command.Flows = 3
	if w = call(makeRequest(command)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var nonces int
	if e = s.DB.QueryRow(ctx, "SELECT count(*) FROM auth_nonces WHERE device_id='learning-device'").Scan(&nonces); e != nil || nonces != 2 {
		t.Fatal("security nonce history", nonces, e)
	}
	if _, e = s.DB.Exec(ctx, "UPDATE devices SET revoked=true WHERE id='learning-device'"); e != nil {
		t.Fatal(e)
	}
	command.Action = "observe"
	if w = call(makeRequest(command)); w.Code != 401 {
		t.Fatal("revoked contributor accepted", w.Code)
	}
	var version int
	if e = s.DB.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); e != nil || version != 4 {
		t.Fatal("unexpected schema", version, e)
	}
}
func TestLearningUnconfiguredDoesNotReadIdentityOrWriteState(t *testing.T) {
	a := &API{}
	w := httptest.NewRecorder()
	a.localLearning(w, httptest.NewRequest("POST", "/api/v1/local/learning", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
