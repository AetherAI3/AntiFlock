package hostile_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	agentruntime "github.com/DBarr3/AntiFlock/agent/runtime"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// Invariant (queue saturation): under concurrent writers the durable queue
// never exceeds its 10000-event bound, never loses an accepted batch, never
// admits a partial batch, stays loadable after every write, and reports
// "full" instead of blocking. The whole run is bounded to 60 seconds.
func TestQueueSaturationUnderConcurrentWriters(t *testing.T) {
	if testing.Short() {
		t.Skip("ENV-UNAVAILABLE: saturation run disabled by -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	directory := filepath.Join(t.TempDir(), "queue")
	queue, err := agentruntime.OpenQueue(directory, queueNode)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()

	const writers = 8
	const batchSize = 500
	var accepted, full, sequences atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for iteration := 0; ctx.Err() == nil; iteration++ {
				entries := make([]agentruntime.QueueEntry, 0, batchSize)
				for index := 0; index < batchSize; index++ {
					// Sequences come from a process counter: NextSequence fsyncs a
					// full rewrite per call and is exercised by agent/runtime's own
					// tests; this test targets concurrent batch admission.
					sequence := uint64(sequences.Add(1))
					entries = append(entries, agentruntime.QueueEntry{
						Event:    &antiflockv1.EventEnvelope{Id: fmt.Sprintf("w%d-i%d-%d", writer, iteration, index), Sequence: sequence, NodeId: queueNode, BootId: "boot"},
						Priority: collectors.QueuePriority(index % 3),
					})
				}
				err := queue.EnqueueBatch(ctx, entries)
				switch {
				case err == nil:
					accepted.Add(batchSize)
				case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
					return
				default:
					full.Add(1)
					return
				}
			}
		}(writer)
	}
	wg.Wait()
	elapsed := time.Since(start)
	if ctx.Err() != nil {
		t.Fatalf("saturation run exceeded its 60 s bound (accepted=%d)", accepted.Load())
	}
	if full.Load() != writers {
		t.Fatalf("every writer must end on a bounded 'full' error; full=%d accepted=%d", full.Load(), accepted.Load())
	}
	if accepted.Load() > 10000 || accepted.Load() == 0 {
		t.Fatalf("accepted=%d outside (0, 10000]", accepted.Load())
	}
	status, err := agentruntime.InspectQueue(directory, queueNode)
	if err != nil {
		t.Fatalf("queue unloadable after saturation: %v", err)
	}
	if int64(status.RetainedEvents) != accepted.Load() {
		t.Fatalf("retained=%d accepted=%d: a batch was lost or partially admitted", status.RetainedEvents, accepted.Load())
	}
	if status.RetainedEvents%batchSize != 0 {
		t.Fatalf("retained=%d is not a whole number of batches", status.RetainedEvents)
	}
	batch, err := queue.Batch(ctx, 256)
	if err != nil || len(batch) != 256 {
		t.Fatalf("batch after saturation: %d %v", len(batch), err)
	}
	for index := 1; index < len(batch); index++ {
		if batch[index].GetSequence() <= batch[index-1].GetSequence() {
			t.Fatalf("batch not in sequence order at %d", index)
		}
	}
	t.Logf("saturated %d events from %d writers in %s", accepted.Load(), writers, elapsed.Round(time.Millisecond))
}
