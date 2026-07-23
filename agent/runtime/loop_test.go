package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	"github.com/DBarr3/AntiFlock/internal/model"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

type submitterFunc func(context.Context, *antiflockv1.SubmitEventBatchRequest) (*antiflockv1.EventBatchAck, error)

func (function submitterFunc) Submit(ctx context.Context, request *antiflockv1.SubmitEventBatchRequest) (*antiflockv1.EventBatchAck, error) {
	return function(ctx, request)
}

func TestRunRetriesContinuousCollectionAfterTransientFailure(t *testing.T) {
	queue, err := OpenQueue(t.TempDir(), "node-agent-1")
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	loop, err := NewLoop(LoopConfig{
		DeploymentID: "deployment-1", NodeID: "node-agent-1", BootID: "boot-1", Interval: time.Second, Queue: queue,
		Collector: CollectorFunc(func(context.Context) (*collectors.Collection, error) {
			calls++
			if calls == 1 { return nil, errors.New("temporary collector failure") }
			cancel()
			return &collectors.Collection{Snapshot: &antiflockv1.ObservationSnapshot{}}, nil
		}),
		Signer: collectors.EventSignerFunc(func(*model.EventEnvelope) error { return nil }),
		Submitter: submitterFunc(func(context.Context, *antiflockv1.SubmitEventBatchRequest) (*antiflockv1.EventBatchAck, error) { return nil, errors.New("unexpected submission") }),
	})
	if err != nil { t.Fatal(err) }
	if err := loop.Run(ctx); err != nil { t.Fatalf("continuous retry returned %v", err) }
	if calls != 2 { t.Fatalf("collection attempts = %d, want 2", calls) }
}
