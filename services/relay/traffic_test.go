package relay

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestLiveTCPBytesCountBeforeLongLivedStreamCloses(t *testing.T) {
	origin, from := net.Pipe()
	to, client := net.Pipe()
	defer origin.Close()
	defer client.Close()
	var counter atomic.Uint64
	var last atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer from.Close()
		defer to.Close()
		io.Copy(activityWriter{Writer: to, last: &last, counter: &counter}, from)
	}()
	body := bytes.Repeat([]byte("v"), 128*1024)
	written := make(chan error, 1)
	go func() { _, e := origin.Write(body); written <- e }()
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	read := make([]byte, len(body))
	if _, e := io.ReadFull(client, read); e != nil {
		t.Fatal(e)
	}
	if e := <-written; e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for counter.Load() != uint64(len(body)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("copy already closed, not live accounting")
	default:
	}
	if counter.Load() != uint64(len(body)) || !bytes.Equal(body, read) || last.Load() == 0 {
		t.Fatal("live relay traffic missing", counter.Load())
	}
	origin.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("copy failed to close")
	}
	if counter.Load() != uint64(len(body)) {
		t.Fatal("close double counted payload")
	}
}
