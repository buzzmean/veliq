package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Mailer sends one plain-text letter. The account API refuses to start a login
// when no mailer is configured.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// SMTPMailer uses implicit TLS on port 465 and mandatory STARTTLS elsewhere;
// credentials never travel over a plain connection.
type SMTPMailer struct {
	Addr     string // host:port
	From     string
	Username string
	Password string
	// TLSConfig replaces the default client TLS configuration when set
	// (tests with a local server). ServerName defaults to the dial host.
	TLSConfig *tls.Config
}

func (m SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	host, port, e := net.SplitHostPort(m.Addr)
	if e != nil || m.From == "" || strings.ContainsAny(to+m.From, "\r\n") {
		return errors.New("invalid mail configuration")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(15 * time.Second)
	}
	dialer := &net.Dialer{Deadline: deadline}
	cfg := m.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg = cfg.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	var conn net.Conn
	if port == "465" {
		conn, e = tls.DialWithDialer(dialer, "tcp", m.Addr, cfg)
	} else {
		conn, e = dialer.DialContext(ctx, "tcp", m.Addr)
	}
	if e != nil {
		return e
	}
	conn.SetDeadline(deadline)
	c, e := smtp.NewClient(conn, host)
	if e != nil {
		conn.Close()
		return e
	}
	defer c.Close()
	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("mail server does not offer STARTTLS")
		}
		if e = c.StartTLS(cfg); e != nil {
			return e
		}
	}
	user := m.Username
	if user == "" {
		user = m.From
	}
	if m.Password != "" {
		if e = c.Auth(smtp.PlainAuth("", user, m.Password, host)); e != nil {
			return e
		}
	}
	if e = c.Mail(m.From); e != nil {
		return e
	}
	if e = c.Rcpt(to); e != nil {
		return e
	}
	w, e := c.Data()
	if e != nil {
		return e
	}
	msg := fmt.Sprintf("From: VELIQ <%s>\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n",
		m.From, to, mime.QEncoding.Encode("utf-8", subject), time.Now().Format(time.RFC1123Z), strings.ReplaceAll(body, "\n", "\r\n"))
	if _, e = w.Write([]byte(msg)); e != nil {
		return e
	}
	if e = w.Close(); e != nil {
		return e
	}
	return c.Quit()
}
