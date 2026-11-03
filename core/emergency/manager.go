package emergency

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/buzzmean/neexitlag/core/ipc"
	"github.com/buzzmean/neexitlag/core/security"
)

type Status struct {
	Configured bool `json:"configured"`
	State string `json:"state"`
	OwnerSID string `json:"owner_sid"`
}

// Manager runs cleanup independently of a short IPC connection. Completion is
// explicit; a timeout, disconnected GUI or failed cleanup never means success.
type Manager struct {
	// Read-only status keeps the independent watchdog from mistaking a deliberate
	// cleanup for an unresponsive service and requesting recovery.
	IdleStatus func() any
	auth *Authenticator
	stop func() error
	mu sync.Mutex
	state string
}
func NewManager(auth *Authenticator, stop func() error) *Manager {
	return &Manager{auth:auth,stop:stop,state:"READY"}
}
func (m *Manager) Status() Status {
	m.mu.Lock()
	state:=m.state
	m.mu.Unlock()
	return Status{m.auth.Configured(),state,m.auth.owner}
}
func (m *Manager) Wrap(next ipc.Handler) ipc.Handler {
	return func(ctx context.Context,method string,raw json.RawMessage)(any,error) {
		switch method {
		case "emergency.status":
			return m.Status(),nil
		case "emergency.finish":
			s:=m.Status()
			if s.State!="STOPPED" { return nil,errors.New("EMERGENCY_STOP_NOT_CONFIRMED") }
			return s,nil
		case "emergency.stop":
			defer clear(raw)
			var q struct { Password []byte `json:"password"` }
			defer func(){clear(q.Password)}()
			if len(raw)>2048 || security.Parse(raw,&q)!=nil { return nil,ErrPassword }
			if err:=m.auth.Verify(q.Password);err!=nil { return nil,err }
			if err:=ctx.Err();err!=nil { return nil,errors.New("EMERGENCY_REQUEST_CANCELLED") }
			m.mu.Lock()
			if m.state!="STOPPING" && m.state!="STOPPED" {
				m.state="STOPPING"
				go func(){
					err:=m.stop()
					m.mu.Lock()
					defer m.mu.Unlock()
					if err!=nil {m.state="CLEANUP_FAILED"} else {m.state="STOPPED"}
				}()
			}
			m.mu.Unlock()
			return m.Status(),nil
		default:
			m.mu.Lock();state:=m.state;m.mu.Unlock()
			if state!="READY" {
				if method=="status" && m.IdleStatus!=nil {return m.IdleStatus(),nil}
				return nil,errors.New("EMERGENCY_STOP_IN_PROGRESS")
			}
			return next(ctx,method,raw)
		}
	}
}
