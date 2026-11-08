// Package ipc defines authenticated, versioned, bounded local request/reply messages.
package ipc

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/security"
	"io"
	"sync"
	"time"
)

const Version = 1
const MaxMessage = 65536

type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	SentAt  time.Time       `json:"sent_at"`
	Token   string          `json:"token"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
}
type Response struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Data    any    `json:"data,omitempty"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

func Read(r io.Reader, v any) error {
	var head [4]byte
	if _, e := io.ReadFull(r, head[:]); e != nil {
		return e
	}
	size := binary.BigEndian.Uint32(head[:])
	if size == 0 || size > MaxMessage {
		return errors.New("invalid IPC message length")
	}
	b := make([]byte, size)
	defer clear(b)
	if _, e := io.ReadFull(r, b); e != nil {
		return e
	}
	return security.Parse(b, v)
}
func Write(w io.Writer, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) > MaxMessage {
		return errors.New("IPC message exceeds limit")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, e = w.Write(h[:]); e != nil {
		return e
	}
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}

type Handler func(context.Context, string, json.RawMessage) (any, error)
type Server struct {
	// AfterReply observes a completed write, never an unacknowledged request.
	AfterReply func(method string, response Response, writeError error)
	Token  string
	Handle Handler
	mu     sync.Mutex
	seen   map[string]time.Time
}

func New(token string, h Handler) (*Server, error) {
	if len(token) < 32 {
		return nil, errors.New("IPC requires at least 128-bit token")
	}
	return &Server{Token: token, Handle: h, seen: make(map[string]time.Time)}, nil
}
func (s *Server) Execute(ctx context.Context, q Request, now time.Time) Response {
	reply := Response{Version: Version, ID: q.ID}
	reject := func(code, msg string) Response { reply.Code = code; reply.Error = msg; return reply }
	if q.Version != Version {
		return reject("incompatible_version", "service IPC version mismatch")
	}
	if q.ID == "" || len(q.ID) > 128 || q.SentAt.After(now.Add(30*time.Second)) || now.Sub(q.SentAt) > time.Minute {
		return reject("invalid_request", "invalid request identity or timestamp")
	}
	if len(q.Token) != len(s.Token) || subtle.ConstantTimeCompare([]byte(q.Token), []byte(s.Token)) != 1 {
		return reject("unauthorized", "local authentication failed")
	}
	s.mu.Lock()
	for id, exp := range s.seen {
		if !exp.After(now) {
			delete(s.seen, id)
		}
	}
	_, replay := s.seen[q.ID]
	if replay || len(s.seen) >= 4096 {
		s.mu.Unlock()
		return reject("replay_or_capacity", "request replay or server busy")
	}
	s.seen[q.ID] = now.Add(2 * time.Minute)
	s.mu.Unlock()
	data, e := s.Handle(ctx, q.Method, q.Payload)
	if e != nil {
		return reject("request_failed", e.Error())
	}
	reply.OK = true
	reply.Data = data
	return reply
}
func (s *Server) Serve(ctx context.Context, rw io.ReadWriter) error {
	var q Request
	if e := Read(rw, &q); e != nil {
		return Write(rw, Response{Version: Version, Code: "invalid_response", Error: "invalid request frame"})
	}
	defer clear(q.Payload)
	reply := s.Execute(ctx, q, time.Now())
	err := Write(rw, reply)
	if s.AfterReply != nil {s.AfterReply(q.Method,reply,err)}
	return err
}
