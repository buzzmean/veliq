package windowsplatform

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/localstrategy"
)

type deferredStreamFixture struct {
	net.Conn
	data       []byte
	chunk      int
	reads      int
	stallEmpty bool
}

func (c *deferredStreamFixture) SetReadDeadline(time.Time) error { return nil }
func (c *deferredStreamFixture) Read(p []byte) (int, error) {
	c.reads++
	if len(c.data) == 0 {
		if c.stallEmpty {
			return 0, nil
		}
		return 0, io.EOF
	}
	if c.chunk > 0 && len(p) > c.chunk {
		p = p[:c.chunk]
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}

func TestDeferredTinyReadsAndTLSRecordsPreserveFollowingEarlyData(t *testing.T) {
	hello := deferredMLKEMHello(t)
	// Even the four-byte handshake header spans records. Following encrypted
	// records belong to the caller and must survive the pre-read unchanged.
	var wire []byte
	for p := hello[5:]; len(p) > 0; {
		n := 2
		if len(p) < n {
			n = len(p)
		}
		wire = append(wire, 22, 3, 3, 0, byte(n))
		wire = append(wire, p[:n]...)
		p = p[n:]
	}
	wire = append(wire, 20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 4, 1, 2, 3, 4)
	for _, chunk := range []int{1, 7, 4096} {
		c := &deferredStreamFixture{data: append([]byte(nil), wire...), chunk: chunk}
		prefix, domain, reason := ReadDeferredHello(c)
		tail, err := io.ReadAll(c)
		if err != nil || domain != "web.telegram.org" || reason != "REASSEMBLY_COMPLETE" || !bytes.Equal(append(prefix, tail...), wire) {
			t.Fatal(chunk, domain, reason, err)
		}
	}
}

func TestDeferredStreamByteAndZeroProgressBoundsPreservePrefix(t *testing.T) {
	oversize := bytes.Repeat([]byte{'G'}, localstrategy.MaxHelloBytes+27)
	c := &deferredStreamFixture{data: append([]byte(nil), oversize...), chunk: 7}
	prefix, domain, reason := ReadDeferredHello(c)
	if len(prefix) != localstrategy.MaxHelloBytes || domain != "" || reason != "REASSEMBLY_LIMIT" {
		t.Fatal(len(prefix), domain, reason)
	}
	tail, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(append(prefix, tail...), oversize) {
		t.Fatal("bounded read discarded bytes", err)
	}
	c = &deferredStreamFixture{data: []byte{22, 3}, stallEmpty: true}
	prefix, domain, reason = ReadDeferredHello(c)
	if !bytes.Equal(prefix, []byte{22, 3}) || domain != "" || reason != "CLIENTHELLO_NO_PROGRESS" || c.reads != 101 {
		t.Fatal(prefix, domain, reason, c.reads)
	}
}

func TestDeferredHTTPManyReadsAndMalformedTLS(t *testing.T) {
	wire := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: " + string(bytes.Repeat([]byte{'x'}, 256)) + "\r\n\r\n")
	c := &deferredStreamFixture{data: wire, chunk: 1}
	got, domain, reason := ReadDeferredHello(c)
	if !bytes.Equal(got, wire) || domain != "example.com" || reason != "HTTP_HOST" {
		t.Fatal(domain, reason)
	}
	for _, raw := range [][]byte{{22, 3, 3, 0, 0}, {22, 3, 3, 255, 255}, {22, 3, 3, 0, 4, 1, 255, 255, 255}} {
		c = &deferredStreamFixture{data: raw, chunk: 1}
		got, domain, reason = ReadDeferredHello(c)
		if !bytes.Equal(got, raw) || domain != "" || reason != "REASSEMBLY_LIMIT" {
			t.Fatal(domain, reason)
		}
	}
}
