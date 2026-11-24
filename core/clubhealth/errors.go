package clubhealth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
)

// ErrorCode does not serialize err.Error(): it can contain credentials, query
// strings, certificate identities and remote responses.
func ErrorCode(err error) (string, uint32) {
	if err == nil {
		return "OK", 0
	}
	var native syscall.Errno
	if errors.As(err, &native) {
		return "OS_ERROR", uint32(native)
	}
	var authority x509.UnknownAuthorityError
	if errors.As(err, &authority) {
		return "TLS_UNKNOWN_AUTHORITY", 0
	}
	var name x509.HostnameError
	if errors.As(err, &name) {
		return "TLS_HOSTNAME", 0
	}
	var cert x509.CertificateInvalidError
	if errors.As(err, &cert) {
		return "TLS_CERTIFICATE_INVALID", uint32(cert.Reason)
	}
	var verify *tls.CertificateVerificationError
	if errors.As(err, &verify) {
		return "TLS_CERTIFICATE_VERIFY", 0
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return "TLS_RECORD", 0
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsTimeout {
			return "DNS_TIMEOUT", 0
		}
		if dns.IsNotFound {
			return "DNS_NOT_FOUND", 0
		}
		return "DNS_ERROR", 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "DEADLINE", 0
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELED", 0
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "NETWORK_TIMEOUT", 0
	}
	var op *net.OpError
	if errors.As(err, &op) {
		switch op.Op {
		case "dial":
			return "CONNECT_FAILED", 0
		case "read":
			return "READ_FAILED", 0
		case "write":
			return "WRITE_FAILED", 0
		}
	}
	return "ERROR_UNCLASSIFIED", 0
}
