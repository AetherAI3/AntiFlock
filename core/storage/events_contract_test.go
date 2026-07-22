package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

func storageEvent(id, bootID string, sequence uint64, receivedAt time.Time) model.EventEnvelope {
	payload := []byte{0x08, 0x01} // Valid opaque protobuf for an additive event kind.
	digest := sha256.Sum256(payload)
	return model.EventEnvelope{
		ID: id, SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment", NodeID: "node",
		Kind: "test.sequence", ObservedAt: receivedAt, ReceivedAt: receivedAt, Sequence: sequence, BootID: bootID,
		Classification: model.EvidenceDetected, Confidence: 1, Sensitivity: model.SensitivityInternal,
		PayloadTypeURL: "type.googleapis.com/test.SequenceEvent", Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]},
		SourceSignature: model.Signature{
			KeyID: "node", Algorithm: "ED25519", Value: bytes.Repeat([]byte{1}, 64), SignedAt: receivedAt,
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{2}, 32)},
		},
	}
}

func openEventDatabase(t *testing.T) *storage.DB {
	t.Helper()
	database, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func appendStoredEvent(t *testing.T, database *storage.DB, event model.EventEnvelope) {
	t.Helper()
	inserted, err := database.AppendEvent(context.Background(), event)
	if err != nil || !inserted {
		t.Fatalf("append %s = %v, %v", event.ID, inserted, err)
	}
}

func TestEventSequenceRejectsGapsRegressionsAndReusedBoots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := openEventDatabase(t)
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)

	if _, err := database.AppendEvent(ctx, storageEvent("first-gap", "boot-a", 2, now)); !errors.Is(err, storage.ErrEventSequenceGap) {
		t.Fatalf("first gap error = %v", err)
	}
	first := storageEvent("event-a1", "boot-a", 1, now)
	appendStoredEvent(t, database, first)
	if _, err := database.AppendEvent(ctx, storageEvent("event-a3", "boot-a", 3, now.Add(time.Second))); !errors.Is(err, storage.ErrEventSequenceGap) {
		t.Fatalf("sequence gap error = %v", err)
	}
	appendStoredEvent(t, database, storageEvent("event-a2", "boot-a", 2, now.Add(2*time.Second)))
	if _, err := database.AppendEvent(ctx, storageEvent("event-a1-conflict", "boot-a", 1, now.Add(3*time.Second))); !errors.Is(err, storage.ErrEventSequenceConflict) {
		t.Fatalf("sequence regression error = %v", err)
	}

	if _, err := database.AppendEvent(ctx, storageEvent("event-b2", "boot-b", 2, now.Add(4*time.Second))); !errors.Is(err, storage.ErrEventSequenceGap) {
		t.Fatalf("new boot without reset error = %v", err)
	}
	appendStoredEvent(t, database, storageEvent("event-b1", "boot-b", 1, now.Add(5*time.Second)))
	if _, err := database.AppendEvent(ctx, storageEvent("event-a3-reused", "boot-a", 3, now.Add(6*time.Second))); !errors.Is(err, storage.ErrEventBootRegression) {
		t.Fatalf("reused boot error = %v", err)
	}

	// At-least-once delivery remains idempotent even after that boot closes.
	inserted, err := database.AppendEvent(ctx, first)
	if err != nil || inserted {
		t.Fatalf("closed-boot duplicate = %v, %v", inserted, err)
	}
	events, err := database.ListEventsFromOrdinal(ctx, 0, 10)
	if err != nil || len(events) != 3 {
		t.Fatalf("stored events after rejected transitions = %d, %v", len(events), err)
	}
}

func TestIngestOrdinalSurvivesClockRollbackAndPaginatesExactlyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := openEventDatabase(t)
	base := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	events := []model.EventEnvelope{
		storageEvent("event-first", "boot", 1, base),
		storageEvent("event-clock-rollback", "boot", 2, base.Add(-time.Hour)),
		storageEvent("event-third", "boot", 3, base.Add(time.Hour)),
	}
	for _, event := range events {
		appendStoredEvent(t, database, event)
	}

	var cursor uint64
	for index, want := range events {
		page, err := database.ListEventsFromOrdinal(ctx, cursor, 1)
		if err != nil || len(page) != 1 {
			t.Fatalf("page %d = %#v, %v", index, page, err)
		}
		if page[0].ID != want.ID || page[0].IngestOrdinal != uint64(index+1) {
			t.Fatalf("page %d event = %#v", index, page[0])
		}
		if page[0].IngestOrdinal <= cursor {
			t.Fatalf("ordinal did not advance: %d after %d", page[0].IngestOrdinal, cursor)
		}
		cursor = page[0].IngestOrdinal
	}
	page, err := database.ListEventsFromOrdinal(ctx, cursor, 1)
	if err != nil || len(page) != 0 {
		t.Fatalf("terminal page = %#v, %v", page, err)
	}
}

func TestLatestNodeEventsSelectOneDurableFactPerKindDeterministically(t *testing.T) {
	t.Parallel()
	database := openEventDatabase(t)
	ctx := context.Background()
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	events := []model.EventEnvelope{
		storageEvent("alpha-old", "boot-latest", 1, now),
		storageEvent("beta-latest", "boot-latest", 2, now.Add(2*time.Minute)),
		storageEvent("alpha-tied-first", "boot-latest", 3, now.Add(time.Minute)),
		storageEvent("alpha-tied-last", "boot-latest", 4, now.Add(time.Minute)),
	}
	for index := range events {
		if index == 1 {
			events[index].Kind = "test.beta"
		} else {
			events[index].Kind = "test.alpha"
		}
		appendStoredEvent(t, database, events[index])
	}
	latest, err := database.ListLatestEventsForNode(ctx, "node", []string{"test.beta", "test.alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 || latest[0].Kind != "test.alpha" || latest[0].ID != "alpha-tied-last" ||
		latest[1].Kind != "test.beta" || latest[1].ID != "beta-latest" {
		t.Fatalf("latest events = %#v", latest)
	}
	if _, err := database.ListLatestEventsForNode(ctx, "node", []string{"test.alpha", "test.alpha"}); err == nil {
		t.Fatal("duplicate event kinds were accepted")
	}
}

func TestProjectionCursorIsMonotonicByOrdinalAndUpdateTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := openEventDatabase(t)
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	first := storageEvent("event-one", "boot", 1, now)
	second := storageEvent("event-two", "boot", 2, now.Add(-time.Hour))
	appendStoredEvent(t, database, first)
	appendStoredEvent(t, database, second)

	if err := database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: "topology", LastEventID: second.ID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: "topology", LastEventID: first.ID, UpdatedAt: now.Add(time.Minute),
	}); err == nil {
		t.Fatal("projection cursor moved to an earlier ingest ordinal")
	}
	if err := database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: "topology", LastEventID: second.ID, UpdatedAt: now.Add(-time.Nanosecond),
	}); err == nil {
		t.Fatal("projection cursor update time moved backward")
	}
	if err := database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: "topology", LastIngestOrdinal: 1, LastEventID: second.ID, UpdatedAt: now.Add(time.Minute),
	}); err == nil {
		t.Fatal("projection cursor accepted an ordinal that did not match its event")
	}
	cursor, err := database.GetProjectionCursor(ctx, "topology")
	if err != nil || cursor.LastEventID != second.ID || cursor.LastIngestOrdinal != 2 {
		t.Fatalf("cursor changed after rejected updates: %#v, %v", cursor, err)
	}
}
