package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// Collector is the narrow, read-only observation source consumed by Loop.
type Collector interface { Collect(context.Context) (*collectors.Collection, error) }

// CollectorFunc adapts a verified read-only collection function to the loop.
type CollectorFunc func(context.Context) (*collectors.Collection, error)

func (function CollectorFunc) Collect(ctx context.Context) (*collectors.Collection, error) { return function(ctx) }

// Submitter is satisfied by ingest.Client. It receives only already-signed
// envelopes that have first crossed the durable Queue boundary.
type Submitter interface { Submit(context.Context, *antiflockv1.SubmitEventBatchRequest) (*antiflockv1.EventBatchAck, error) }

type LoopConfig struct {
	DeploymentID string
	NodeID string
	BootID string
	Interval time.Duration
	Collector Collector
	Queue *Queue
	Signer collectors.EventSigner
	Submitter Submitter
	Clock func() time.Time
}

// Loop performs continuous collection without host mutation. Collection
// failure leaves already queued telemetry untouched; submission failure leaves
// the exact signed batch on disk for the next attempt.
type Loop struct {
	config LoopConfig
	builder *collectors.TelemetryBuilder
}

func NewLoop(config LoopConfig) (*Loop, error) {
	if strings.TrimSpace(config.DeploymentID) == "" || strings.TrimSpace(config.NodeID) == "" || strings.TrimSpace(config.BootID) == "" ||
		config.Collector == nil || config.Queue == nil || config.Signer == nil || config.Submitter == nil {
		return nil, errors.New("agent loop requires deployment, node, boot, collector, queue, signer, and submitter")
	}
	if config.Interval == 0 { config.Interval = 30 * time.Second }
	if config.Interval < time.Second || config.Interval > 24*time.Hour { return nil, errors.New("agent collection interval must be between one second and 24 hours") }
	if config.Clock == nil { config.Clock = func() time.Time { return time.Now().UTC() } }
	builder, err := collectors.NewTelemetryBuilder(config.DeploymentID, config.NodeID, config.BootID, config.Queue, config.Signer, config.Clock)
	if err != nil { return nil, err }
	return &Loop{config: config, builder: builder}, nil
}

// Run executes an immediate collection, then repeats at the configured
// interval. A collection or delivery failure leaves the durable queue intact
// and is retried on the next interval; --once callers use RunOnce directly
// when they need the error returned to their supervisor.
func (loop *Loop) Run(ctx context.Context) error {
	if loop == nil { return errors.New("agent loop is required") }
	for {
		_ = loop.RunOnce(ctx)
		if ctx.Err() != nil { return nil }
		timer := time.NewTimer(loop.config.Interval)
		select { case <-ctx.Done(): timer.Stop(); return nil; case <-timer.C: }
	}
}

func (loop *Loop) RunOnce(ctx context.Context) error {
	if loop == nil { return errors.New("agent loop is required") }
	collection, err := loop.config.Collector.Collect(ctx)
	if err != nil { return fmt.Errorf("collect agent metadata: %w", err) }
	for _, observation := range collection.Observations() {
		if _, err := loop.builder.BuildAndEnqueue(ctx, loop.config.Queue, observation); err != nil { return fmt.Errorf("persist agent observation: %w", err) }
	}
	return loop.drain(ctx)
}

func (loop *Loop) drain(ctx context.Context) error {
	for {
		events, err := loop.config.Queue.Batch(ctx, 256)
		if err != nil { return err }
		if len(events) == 0 { return nil }
		batchID := fmt.Sprintf("batch-%s-%s-%d-%d", loop.config.NodeID, loop.config.BootID, events[0].GetSequence(), events[len(events)-1].GetSequence())
		request := &antiflockv1.SubmitEventBatchRequest{Batch: &antiflockv1.EventBatch{BatchId: batchID, NodeId: loop.config.NodeID, Events: events}}
		if _, err := loop.config.Submitter.Submit(ctx, request); err != nil { return fmt.Errorf("submit durable agent batch: %w", err) }
		if err := loop.config.Queue.Acknowledge(ctx, events); err != nil { return fmt.Errorf("acknowledge durable agent batch: %w", err) }
	}
}
