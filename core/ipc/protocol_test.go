package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestAuthenticationVersionReplayAndFraming(t *testing.T) {
	s, e := New("0123456789abcdef0123456789abcdef", func(context.Context, string, json.RawMessage) (any, error) {
		return map[string]bool{"ready": true}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	q := Request{Version: Version, ID: "nonce", SentAt: now, Token: s.Token, Method: "status"}
	var b bytes.Buffer
	if e = Write(&b, q); e != nil {
		t.Fatal(e)
	}
	var decoded Request
	if e = Read(&b, &decoded); e != nil {
		t.Fatal(e)
	}
	if !s.Execute(context.Background(), decoded, now).OK {
		t.Fatal("authenticated request")
	}
	if s.Execute(context.Background(), decoded, now).Code != "replay_or_capacity" {
		t.Fatal("replay")
	}
	q.ID = "other"
	q.Token = "wrong"
	if s.Execute(context.Background(), q, now).Code != "unauthorized" {
		t.Fatal("token")
	}
	q.Version = 99
	if s.Execute(context.Background(), q, now).Code != "incompatible_version" {
		t.Fatal("version")
	}
	if e = Read(bytes.NewReader([]byte{255, 255, 255, 255}), &decoded); e == nil {
		t.Fatal("unbounded frame")
	}
}
func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, b []byte) { var q Request; Read(bytes.NewReader(b), &q) })
}
