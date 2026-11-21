package transport_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/tools/labcert"
	"github.com/quic-go/quic-go"
	"reflect"
	"testing"
	"time"
)

// Capture the actual peer-decoded QUIC ClientHello on loopback, not guessed tls.Config.
// This is parameter evidence, NOT a standardized JA4 hash or an ISP/DPI verdict.
func TestRelayClientHelloObservedOnWire(t *testing.T) {
	for _, ticket := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "ticket"}[ticket], func(t *testing.T) {
			server, client, err := labcert.Pair()
			if err != nil {
				t.Fatal(err)
			}
			server.NextProtos = []string{"neexitlag/3", "neexitlag/2", transport.ALPN}
			type hello struct {
				SNI              string
				ALPN             []string
				Versions         []uint16
				Ciphers          []uint16
				Groups           []tls.CurveID
				SignatureSchemes []tls.SignatureScheme
				Points           []uint8
			}
			seen := make(chan hello, 1)
			server.GetConfigForClient = func(c *tls.ClientHelloInfo) (*tls.Config, error) {
				seen <- hello{c.ServerName, append([]string(nil), c.SupportedProtos...), append([]uint16(nil), c.SupportedVersions...), append([]uint16(nil), c.CipherSuites...), append([]tls.CurveID(nil), c.SupportedCurves...), append([]tls.SignatureScheme(nil), c.SignatureSchemes...), append([]uint8(nil), c.SupportedPoints...)}
				return nil, nil
			}
			listener, err := quic.ListenAddr("127.0.0.1:0", server, transport.QUICConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := listener.Accept(ctx)
				if e == nil {
					<-ctx.Done()
					c.CloseWithError(0, "fixture")
				}
			}()
			if ticket {
				_, _ = transport.DialWithTicket(ctx, listener.Addr().String(), client, []byte("local unauthenticated fixture"))
			} else {
				c, e := transport.Dial(ctx, listener.Addr().String(), client)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
			}
			select {
			case got := <-seen:
				want := []string{transport.ALPN}
				if ticket {
					want = []string{"neexitlag/3", "neexitlag/2"}
				}
				if got.SNI != "" || !reflect.DeepEqual(got.ALPN, want) || !reflect.DeepEqual(got.Versions, []uint16{tls.VersionTLS13}) || len(got.Ciphers) == 0 || len(got.Groups) == 0 {
					t.Fatal(got)
				}
				raw, _ := json.Marshal(got)
				t.Log(string(raw))
			default:
				t.Fatal("no decoded ClientHello")
			}
			cancel()
			<-done
		})
	}
}
