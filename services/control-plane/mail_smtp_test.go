package controlplane

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSMTP is a minimal in-process SMTP server speaking just enough of the
// protocol for SMTPMailer: EHLO, AUTH PLAIN, MAIL/RCPT/DATA, QUIT, plus
// STARTTLS or implicit TLS. It verifies real TLS client behaviour instead of
// mocking the transport.
type fakeSMTP struct {
	username string
	password string
	mailer   SMTPMailer
	data     chan string // raw DATA payload
	err      chan error
}

func smtpTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"smtp.test"},
	}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// startFakeSMTP binds 127.0.0.1:port and serves one connection. implicitTLS
// selects the port-465 style handshake; otherwise STARTTLS is offered (or
// hidden when offerStartTLS is false).
func startFakeSMTP(t *testing.T, port string, implicitTLS, offerStartTLS bool) *fakeSMTP {
	t.Helper()
	cert, pool := smtpTestCert(t)
	ln, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if e != nil {
		t.Skipf("port %s unavailable: %v", port, e)
	}
	f := &fakeSMTP{username: "robot@smtp.test", password: "secret", data: make(chan string, 1), err: make(chan error, 1)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if implicitTLS {
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if e := tlsConn.Handshake(); e != nil {
				f.err <- e
				return
			}
			conn = tlsConn
		}
		f.err <- f.serve(conn, &cert, offerStartTLS)
	}()
	f.mailer = SMTPMailer{
		Addr:      net.JoinHostPort("127.0.0.1", port),
		From:      "cabinet@veliq.app",
		Username:  f.username,
		Password:  f.password,
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "smtp.test", MinVersion: tls.VersionTLS12},
	}
	return f
}

func (f *fakeSMTP) serve(conn net.Conn, cert *tls.Certificate, offerStartTLS bool) error {
	r := bufio.NewReader(conn)
	write := func(s string) error {
		_, e := conn.Write([]byte(s + "\r\n"))
		return e
	}
	if e := write("220 smtp.test ready"); e != nil {
		return e
	}
	_, secure := conn.(*tls.Conn)
	for {
		line, e := r.ReadString('\n')
		if e != nil {
			return e
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			if !secure && offerStartTLS {
				if e := write("250-smtp.test\r\n250-STARTTLS\r\n250 AUTH PLAIN"); e != nil {
					return e
				}
			} else if e := write("250-smtp.test\r\n250 AUTH PLAIN"); e != nil {
				return e
			}
		case upper == "STARTTLS":
			if e := write("220 go ahead"); e != nil {
				return e
			}
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
			if e := tlsConn.Handshake(); e != nil {
				return e
			}
			conn = tlsConn
			r = bufio.NewReader(conn)
			secure = true
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				return write("535 credentials missing")
			}
			raw, e := base64.StdEncoding.DecodeString(parts[2])
			if e != nil {
				return write("535 bad encoding")
			}
			fields := strings.Split(string(raw), "\x00")
			if len(fields) != 3 || fields[1] != f.username || fields[2] != f.password {
				return write("535 wrong credentials")
			}
			if e := write("235 authenticated"); e != nil {
				return e
			}
		case strings.HasPrefix(upper, "MAIL FROM:"):
			if e := write("250 sender ok"); e != nil {
				return e
			}
		case strings.HasPrefix(upper, "RCPT TO:"):
			if e := write("250 recipient ok"); e != nil {
				return e
			}
		case upper == "DATA":
			if e := write("354 end with ."); e != nil {
				return e
			}
			var b strings.Builder
			for {
				l, e := r.ReadString('\n')
				if e != nil {
					return e
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.data <- b.String()
			if e := write("250 queued"); e != nil {
				return e
			}
		case upper == "QUIT":
			return write("221 bye")
		default:
			if e := write("502 unsupported"); e != nil {
				return e
			}
		}
	}
}

func TestSMTPMailerImplicitTLSRoundTrip(t *testing.T) {
	f := startFakeSMTP(t, "465", true, false)
	if e := f.mailer.Send(context.Background(), "player@example.com", "Код входа VELIQ", "Ваш код: 123456\nСтрока два"); e != nil {
		t.Fatal("send over implicit TLS:", e)
	}
	select {
	case payload := <-f.data:
		if !strings.Contains(payload, "From: VELIQ <cabinet@veliq.app>") {
			t.Fatal("From header", payload)
		}
		if !strings.Contains(payload, "To: player@example.com") {
			t.Fatal("To header", payload)
		}
		if !strings.Contains(strings.ToLower(payload), "=?utf-8?q?") {
			t.Fatal("subject not Q-encoded", payload)
		}
		if !strings.Contains(payload, "Ваш код: 123456\r\nСтрока два\r\n") {
			t.Fatal("body CRLF normalization", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no DATA received")
	}
	if e := <-f.err; e != nil {
		t.Fatal("server:", e)
	}
}

func TestSMTPMailerSTARTTLSRoundTrip(t *testing.T) {
	f := startFakeSMTP(t, "587", false, true)
	if e := f.mailer.Send(context.Background(), "club@example.com", "Код входа VELIQ", "Ваш код: 654321"); e != nil {
		t.Fatal("send over STARTTLS:", e)
	}
	select {
	case payload := <-f.data:
		if !strings.Contains(payload, "Ваш код: 654321") {
			t.Fatal("body", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no DATA received")
	}
	if e := <-f.err; e != nil {
		t.Fatal("server:", e)
	}
}

func TestSMTPMailerRefusesPlaintextServer(t *testing.T) {
	f := startFakeSMTP(t, "5587", false, false)
	e := f.mailer.Send(context.Background(), "player@example.com", "s", "b")
	if e == nil || !strings.Contains(e.Error(), "STARTTLS") {
		t.Fatal("plaintext-only server accepted:", e)
	}
}

func TestSMTPMailerRejectsHeaderInjection(t *testing.T) {
	m := SMTPMailer{Addr: "127.0.0.1:1", From: "cabinet@veliq.app"}
	if e := m.Send(context.Background(), "a@b.c\r\nBcc: evil@x", "s", "b"); e == nil {
		t.Fatal("CRLF recipient accepted")
	}
}
