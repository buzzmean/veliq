package browserproxy

import "time"

// Never closes an established socket. The accept path shares this lock so a
// connection cannot enter between the idle check and retiring the listener.
func (s *Server) CloseIfIdle(now time.Time, idle time.Duration) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return true
	}
	if len(s.conns) != 0 || idle <= 0 || now.Sub(s.lastActivity) < idle {
		s.mu.Unlock()
		return false
	}
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	_ = s.l.Close()
	return true
}
