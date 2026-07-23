package runtime

import (
	"context"
	"testing"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

func TestQueuePersistsSignedWireUntilAcknowledged(t *testing.T) {
	queue, err := OpenQueue(t.TempDir(), "node-1")
	if err != nil { t.Fatal(err) }
	sequence, err := queue.NextSequence(context.Background())
	if err != nil { t.Fatal(err) }
	event := &antiflockv1.EventEnvelope{Id: "event-1", NodeId: "node-1", BootId: "boot-1", Sequence: sequence}
	if err := queue.Enqueue(context.Background(), event, collectors.QueuePriorityObservation); err != nil { t.Fatal(err) }
	queue, err = OpenQueue(queue.directory, "node-1")
	if err != nil { t.Fatal(err) }
	batch, err := queue.Batch(context.Background(), 1)
	if err != nil || len(batch) != 1 || batch[0].GetId() != event.GetId() { t.Fatalf("batch=%#v err=%v", batch, err) }
	if err := queue.Acknowledge(context.Background(), batch); err != nil { t.Fatal(err) }
	batch, err = queue.Batch(context.Background(), 1)
	if err != nil || len(batch) != 0 { t.Fatalf("ack left queued events: %#v %v", batch, err) }
}

func TestQueueDoesNotMixBootIDsInOneCoreBatch(t *testing.T) {
	queue, err := OpenQueue(t.TempDir(), "node-1")
	if err != nil { t.Fatal(err) }
	for index, bootID := range []string{"boot-old", "boot-new"} {
		event := &antiflockv1.EventEnvelope{Id: "event-" + bootID, NodeId: "node-1", BootId: bootID, Sequence: uint64(index + 1)}
		if err := queue.Enqueue(context.Background(), event, collectors.QueuePriorityObservation); err != nil { t.Fatal(err) }
	}
	batch, err := queue.Batch(context.Background(), 256)
	if err != nil || len(batch) != 1 || batch[0].GetBootId() != "boot-old" { t.Fatalf("batch=%#v err=%v", batch, err) }
	if err := queue.Acknowledge(context.Background(), batch); err != nil { t.Fatal(err) }
	batch, err = queue.Batch(context.Background(), 256)
	if err != nil || len(batch) != 1 || batch[0].GetBootId() != "boot-new" { t.Fatalf("next batch=%#v err=%v", batch, err) }
}

func TestQueueBatchAdmissionDoesNotPersistPartialCycleWhenFull(t *testing.T) {
	queue, err := OpenQueue(t.TempDir(), "node-1")
	if err != nil { t.Fatal(err) }
	queue.state.Events = make([]queuedEvent, maximumQueueEvents)
	entries := []QueueEntry{
		{Event: &antiflockv1.EventEnvelope{Id: "event-1", NodeId: "node-1", BootId: "boot-1", Sequence: 1}, Priority: collectors.QueuePriorityObservation},
		{Event: &antiflockv1.EventEnvelope{Id: "event-2", NodeId: "node-1", BootId: "boot-1", Sequence: 2}, Priority: collectors.QueuePriorityObservation},
	}
	if err := queue.EnqueueBatch(context.Background(), entries); err == nil { t.Fatal("full queue accepted a partial collection cycle") }
	if len(queue.state.Events) != maximumQueueEvents { t.Fatalf("queue size = %d, want %d", len(queue.state.Events), maximumQueueEvents) }
}

func TestQueueExcludesConcurrentWritersAndReleasesOnClose(t *testing.T) {
	directory := t.TempDir()
	first, err := OpenQueue(directory, "node-1")
	if err != nil { t.Fatal(err) }
	if _, err := OpenQueue(directory, "node-1"); err == nil {
		t.Fatal("second queue writer acquired the active queue")
	}
	if err := first.Close(); err != nil { t.Fatal(err) }
	second, err := OpenQueue(directory, "node-1")
	if err != nil { t.Fatalf("queue did not release writer lock: %v", err) }
	defer second.Close()
}
