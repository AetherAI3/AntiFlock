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
