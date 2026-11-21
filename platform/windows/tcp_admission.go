package windowsplatform

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

const tcpOpenParallel = 128
const tcpOpenPending = 384 // active + waiting; independent of established flow count
const tcpAdmissionTimeout = 5 * time.Second

// tcpAdmission bounds both setup concurrency and queued goroutines/memory.
// Weighted acquisition provides FIFO waiting without blocking packet capture or
// accept. The wait budget is separate from the unchanged real upstream timeout.
// Established streams release admission before any application payload writes.
type tcpAdmission struct {
	pending chan struct{}
	slots   *semaphore.Weighted
}

func newTCPAdmission() *tcpAdmission {
	return &tcpAdmission{pending: make(chan struct{}, tcpOpenPending), slots: semaphore.NewWeighted(tcpOpenParallel)}
}

func (a *tcpAdmission) submit(ctx context.Context, run func(time.Duration, error, func())) bool {
	select {
	case a.pending <- struct{}{}:
	default:
		return false
	}
	started := time.Now()
	go func() {
		wait, cancel := context.WithTimeout(ctx, tcpAdmissionTimeout)
		err := a.slots.Acquire(wait, 1)
		cancel()
		var once sync.Once
		release := func() {
			once.Do(func() {
				if err == nil {
					a.slots.Release(1)
				}
				<-a.pending
			})
		}
		defer release()
		run(time.Since(started), err, release)
	}()
	return true
}
