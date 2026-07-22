package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

func TestEventRetentionSchedulerRunsImmediatelyAndStopsOnCancellation(t *testing.T) {
	t.Parallel()
	database, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Now().UTC()
	payload := []byte{0x08, 0x01}
	payloadDigest := sha256.Sum256(payload)
	event := model.EventEnvelope{
		ID: "scheduler-old-event", SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment", NodeID: "node",
		Kind: "test.retention", ObservedAt: now.Add(-3 * time.Hour), ReceivedAt: now.Add(-3 * time.Hour),
		Sequence: 1, BootID: "boot", Classification: model.EvidenceDetected, Confidence: 1,
		Sensitivity: model.SensitivityInternal, PayloadTypeURL: "type.googleapis.com/test.Retention", Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: payloadDigest[:]},
		SourceSignature: model.Signature{
			KeyID: "node", Algorithm: "ED25519", Value: bytes.Repeat([]byte{1}, 64), SignedAt: now.Add(-3 * time.Hour),
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{2}, 32)},
		},
	}
	if inserted, err := database.AppendEvent(context.Background(), event); err != nil || !inserted {
		t.Fatalf("append retained event = %v, %v", inserted, err)
	}
	stored, err := database.GetEvent(context.Background(), event.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetProjectionCursor(context.Background(), storage.ProjectionCursor{
		Projection: events.APIProjection, LastIngestOrdinal: stored.IngestOrdinal,
		LastReceivedAt: stored.ReceivedAt, LastEventID: stored.ID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runEventRetention(ctx, database, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, getErr := database.GetEvent(context.Background(), event.ID)
		if errors.Is(getErr, storage.ErrEventNotFound) {
			break
		}
		if getErr != nil {
			t.Fatal(getErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("immediate retention pass did not prune the safe old event")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retention scheduler did not stop after cancellation")
	}
	if err := database.VerifyEventRetentionTombstones(context.Background()); err != nil {
		t.Fatalf("verify retention deletion receipt: %v", err)
	}
}

func TestEventRetentionIntervalIsBounded(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		retention time.Duration
		want      time.Duration
	}{
		{time.Minute, time.Minute},
		{12 * time.Hour, 30 * time.Minute},
		{24 * time.Hour, time.Hour},
		{30 * 24 * time.Hour, time.Hour},
	} {
		if got := eventRetentionInterval(test.retention); got != test.want {
			t.Fatalf("eventRetentionInterval(%s) = %s, want %s", test.retention, got, test.want)
		}
	}
}
