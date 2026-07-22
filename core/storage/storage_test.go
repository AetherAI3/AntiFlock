package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestOpenMigratesAndAppendsEventsIdempotently(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "antiflock.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.Health(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.WifiObservation{Ssid: "coffee-shop", ObservedAt: timestamppb.New(now)})
	payloadDigest := sha256.Sum256(payload)
	event := model.EventEnvelope{
		ID: "event_test", SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment_test", NodeID: "node_test",
		Kind: "network.wifi_changed", ObservedAt: now, ReceivedAt: now, Sequence: 1, BootID: "boot_test",
		Classification: model.EvidenceDetected, Confidence: 1, Sensitivity: model.SensitivityInternal,
		PayloadTypeURL: "type.googleapis.com/antiflock.v1.WifiObservation", Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: payloadDigest[:]},
		SourceSignature: model.Signature{
			KeyID: "node_test", Algorithm: "ED25519", Value: bytes.Repeat([]byte{1}, 64), SignedAt: now,
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{2}, 32)},
		},
	}
	inserted, err := database.AppendEvent(ctx, event)
	if err != nil || !inserted {
		t.Fatalf("first append = %v, %v", inserted, err)
	}
	inserted, err = database.AppendEvent(ctx, event)
	if err != nil || inserted {
		t.Fatalf("duplicate append = %v, %v", inserted, err)
	}
	events, err := database.ListEvents(ctx, time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != event.Kind {
		t.Fatalf("unexpected replay: %#v", events)
	}
	conflict := event
	conflict.ID = "event_conflict"
	conflict.Payload, _ = proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.WifiObservation{Ssid: "trusted", ObservedAt: timestamppb.New(now)})
	conflictDigest := sha256.Sum256(conflict.Payload)
	conflict.PayloadDigest.Digest = conflictDigest[:]
	if _, err := database.AppendEvent(ctx, conflict); !errors.Is(err, storage.ErrEventSequenceConflict) {
		t.Fatalf("sequence conflict error = %v", err)
	}
}

func TestEventPaginationDoesNotSkipEqualTimestamps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	now := time.Date(2026, 7, 21, 12, 0, 0, 123, time.UTC)
	payload := []byte{0x08, 0x01}
	digest := sha256.Sum256(payload)
	base := model.EventEnvelope{
		SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment", NodeID: "node", Kind: "test.observed",
		ObservedAt: now, ReceivedAt: now, BootID: "boot", Classification: model.EvidenceDetected,
		Confidence: 1, Sensitivity: model.SensitivityInternal, PayloadTypeURL: "type.googleapis.com/test.Event", Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]},
		SourceSignature: model.Signature{KeyID: "node", Algorithm: "ED25519", Value: bytes.Repeat([]byte{1}, 64), SignedAt: now,
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{2}, 32)}},
	}
	first := base
	first.ID, first.Sequence = "event_a", 1
	second := base
	second.ID, second.Sequence = "event_b", 2
	for _, event := range []model.EventEnvelope{first, second} {
		if inserted, err := database.AppendEvent(ctx, event); err != nil || !inserted {
			t.Fatalf("append %s = %v, %v", event.ID, inserted, err)
		}
	}
	page, err := database.ListEventsPage(ctx, time.Time{}, "", 1)
	if err != nil || len(page) != 1 || page[0].ID != "event_a" {
		t.Fatalf("first page = %#v, %v", page, err)
	}
	page, err = database.ListEventsPage(ctx, page[0].ReceivedAt, page[0].ID, 1)
	if err != nil || len(page) != 1 || page[0].ID != "event_b" {
		t.Fatalf("second page = %#v, %v", page, err)
	}
}

func TestRetentionWaitsForEveryProjectionAndPrunesOnlySafeEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	payload := []byte{0x08, 0x01}
	digest := sha256.Sum256(payload)
	base := model.EventEnvelope{
		SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment", NodeID: "node", Kind: "test.retained",
		ObservedAt: now.Add(-72 * time.Hour), BootID: "boot", Classification: model.EvidenceDetected,
		Confidence: 1, Sensitivity: model.SensitivityInternal, PayloadTypeURL: "type.googleapis.com/test.Event", Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]},
		SourceSignature: model.Signature{KeyID: "node", Algorithm: "ED25519", Value: bytes.Repeat([]byte{1}, 64), SignedAt: now.Add(-72 * time.Hour),
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{2}, 32)}},
	}
	events := []model.EventEnvelope{base, base, base}
	events[0].ID, events[0].Sequence, events[0].ReceivedAt = "event_old_a", 1, now.Add(-72*time.Hour)
	events[1].ID, events[1].Sequence, events[1].ReceivedAt = "event_old_b", 2, now.Add(-48*time.Hour)
	events[2].ID, events[2].Sequence, events[2].ReceivedAt = "event_recent", 3, now.Add(-time.Hour)
	for _, event := range events {
		if inserted, err := database.AppendEvent(ctx, event); err != nil || !inserted {
			t.Fatalf("append %s = %v, %v", event.ID, inserted, err)
		}
	}
	if err := database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: "topology", LastReceivedAt: events[1].ReceivedAt, LastEventID: events[1].ID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.PruneEvents(ctx, now.Add(-24*time.Hour), []string{"topology", "posture"}, 100); !errors.Is(err, storage.ErrRetentionProjectionNotReady) {
		t.Fatalf("missing projection error = %v", err)
	}
	if err := database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: "posture", LastReceivedAt: events[0].ReceivedAt, LastEventID: events[0].ID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := database.PruneEvents(ctx, now.Add(-24*time.Hour), []string{"topology", "posture"}, 100)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("retention result = %#v, %v", result, err)
	}
	remaining, err := database.ListEvents(ctx, time.Time{}, 10)
	if err != nil || len(remaining) != 2 || remaining[0].ID != "event_old_b" || remaining[1].ID != "event_recent" {
		t.Fatalf("remaining events = %#v, %v", remaining, err)
	}
}

func TestProjectionCursorAndAuditRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "antiflock.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	empty, err := database.GetProjectionCursor(ctx, "topology")
	if err != nil || empty.Projection != "topology" || !empty.LastReceivedAt.IsZero() {
		t.Fatalf("empty cursor = %#v, %v", empty, err)
	}
	now := time.Now().UTC()
	payload := []byte{0x08, 0x01}
	digest := sha256.Sum256(payload)
	event := model.EventEnvelope{
		ID: "event_cursor", SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment", NodeID: "node",
		Kind: "test.cursor", ObservedAt: now, ReceivedAt: now, Sequence: 1, BootID: "boot",
		Classification: model.EvidenceDetected, Confidence: 1, Sensitivity: model.SensitivityInternal,
		PayloadTypeURL: "type.googleapis.com/test.Event", Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]},
		SourceSignature: model.Signature{KeyID: "node", Algorithm: "ED25519", Value: bytes.Repeat([]byte{1}, 64), SignedAt: now,
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{2}, 32)}},
	}
	if inserted, err := database.AppendEvent(ctx, event); err != nil || !inserted {
		t.Fatalf("append cursor event = %v, %v", inserted, err)
	}
	want := storage.ProjectionCursor{Projection: "topology", LastReceivedAt: now, LastEventID: event.ID, UpdatedAt: now}
	if err := database.SetProjectionCursor(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := database.GetProjectionCursor(ctx, "topology")
	if err != nil || got.LastEventID != want.LastEventID {
		t.Fatalf("cursor = %#v, %v", got, err)
	}
	entry := model.AuditEntry{
		ID: "audit_one", KeyID: "audit:test", OccurredAt: now, ActorType: "test", ActorID: "tester",
		Action: "test.recorded", ResourceType: "test", ResourceID: "one", Outcome: "success",
		Details: json.RawMessage(`{"ok":true}`), EntryHash: "hash_one", Signature: "signature",
	}
	if err := database.InsertAuditEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	hash, err := database.LastAuditHash(ctx)
	if err != nil || hash != entry.EntryHash {
		t.Fatalf("last hash = %q, %v", hash, err)
	}
}
