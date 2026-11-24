package transport_test

import (
	"github.com/buzzmean/veliq/core/transport"
	"testing"
)

func TestDownloadCreditBoundedAndServerSecurityUnchanged(t *testing.T) {
	c, s := transport.ClientQUICConfig(), transport.QUICConfig()
	if c.InitialStreamReceiveWindow != 256*1024 || c.MaxStreamReceiveWindow != 2*1024*1024 || c.InitialConnectionReceiveWindow != 1024*1024 || c.MaxConnectionReceiveWindow != 8*1024*1024 {
		t.Fatal("download budget changed", c)
	}
	if s.MaxStreamReceiveWindow != 256*1024 || s.MaxConnectionReceiveWindow != 1024*1024 {
		t.Fatal("server budget changed")
	}
	if c.Allow0RTT || s.Allow0RTT || c.MaxIncomingStreams != s.MaxIncomingStreams || c.MaxIncomingUniStreams != s.MaxIncomingUniStreams || c.HandshakeIdleTimeout != s.HandshakeIdleTimeout || c.MaxIdleTimeout != s.MaxIdleTimeout || !c.EnableDatagrams {
		t.Fatal("security/stream/time bounds changed")
	}
	c.MaxStreamReceiveWindow = 1
	if transport.ClientQUICConfig().MaxStreamReceiveWindow != 2*1024*1024 {
		t.Fatal("shared mutable config")
	}
}
