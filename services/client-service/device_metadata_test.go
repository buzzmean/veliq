package clientservice

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/deviceinfo"
)

type metadataFixture struct {
	supported bool
	cancel    context.CancelFunc
	posts     int
	details   deviceinfo.Details
}

func (f *metadataFixture) SupportsDeviceMetadata(context.Context) (bool, error) {
	if !f.supported {
		f.cancel()
	}
	return f.supported, nil
}
func (f *metadataFixture) DeviceMetadata(_ context.Context, d deviceinfo.Details) error {
	f.posts++
	f.details = d
	f.cancel()
	return nil
}
func TestDeviceMetadataWorkerRespectsCapabilityAndCancellation(t *testing.T) {
	for _, supported := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		f := &metadataFixture{supported: supported, cancel: cancel}
		c := &Controller{}
		c.runDeviceMetadata(ctx, f)
		cancel()
		if supported {
			hostname, err := os.Hostname()
			if err != nil || f.posts != 1 || f.details.ComputerName != hostname || !f.details.Valid() {
				t.Fatalf("Имя Windows не передано: posts=%d error=%v", f.posts, err)
			}
		} else if f.posts != 0 {
			t.Fatal("Сведения отправлены серверу без поддержки метода")
		}
	}
}
