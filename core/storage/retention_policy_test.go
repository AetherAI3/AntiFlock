package storage_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

func TestRetentionClassAndSensitivityOverridesOnlyReduceRetention(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := openEventDatabase(t)
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	events := []model.EventEnvelope{
		storageEvent("detected-internal-kept", "boot", 1, now.Add(-10*24*time.Hour)),
		storageEvent("verified-override-pruned", "boot", 2, now.Add(-10*24*time.Hour)),
		storageEvent("secret-override-pruned", "boot", 3, now.Add(-3*24*time.Hour)),
		storageEvent("secret-recent-kept", "boot", 4, now.Add(-24*time.Hour)),
		storageEvent("default-pruned", "boot", 5, now.Add(-31*24*time.Hour)),
	}
	events[1].Classification = model.EvidenceReported
	events[2].Sensitivity = model.SensitivitySecret
	events[3].Classification, events[3].Sensitivity = model.EvidenceReported, model.SensitivitySecret
	for _, event := range events {
		appendStoredEvent(t, database, event)
	}
	auditEntry := model.AuditEntry{
		ID: "audit-retention-guard", KeyID: "audit:test", OccurredAt: now,
		ActorType: "system", ActorID: "retention-test", Action: "retention.guard",
		ResourceType: "event", ResourceID: "all", Outcome: "success",
		Details: json.RawMessage(`{"auditRetention":"forever"}`), EntryHash: "audit-hash", Signature: "signature",
	}
	if err := database.InsertAuditEntry(ctx, auditEntry); err != nil {
		t.Fatal(err)
	}
	if err := database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: "topology", LastEventID: events[len(events)-1].ID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := database.PruneEventsWithCutoffs(ctx, storage.EventRetentionCutoffs{
		DefaultBefore: now.Add(-30 * 24 * time.Hour),
		ByClassification: map[model.EvidenceClass]time.Time{
			model.EvidenceReported: now.Add(-5 * 24 * time.Hour),
		},
		BySensitivity: map[model.Sensitivity]time.Time{
			model.SensitivitySecret: now.Add(-2 * 24 * time.Hour),
		},
	}, []string{"topology"}, 100)
	if err != nil || result.Deleted != 3 || result.TombstoneHash == "" {
		t.Fatalf("retention result = %#v, %v", result, err)
	}
	remaining, err := database.ListEventsFromOrdinal(ctx, 0, 10)
	if err != nil || len(remaining) != 2 || remaining[0].ID != events[0].ID || remaining[1].ID != events[3].ID {
		t.Fatalf("remaining events = %#v, %v", remaining, err)
	}
	if err := database.VerifyEventRetentionTombstones(ctx); err != nil {
		t.Fatalf("verify tombstones: %v", err)
	}
	auditEntries, err := database.ListAuditEntries(ctx, 10)
	if err != nil || len(auditEntries) != 1 || auditEntries[0].ID != auditEntry.ID {
		t.Fatalf("audit was compacted by event retention: %#v, %v", auditEntries, err)
	}
}

func TestRetentionCutoffCannotSilentlyExtendDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := openEventDatabase(t)
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	_, err := database.PruneEventsWithCutoffs(ctx, storage.EventRetentionCutoffs{
		DefaultBefore: now.Add(-14 * 24 * time.Hour),
		BySensitivity: map[model.Sensitivity]time.Time{
			model.SensitivitySecret: now.Add(-30 * 24 * time.Hour),
		},
	}, []string{"topology"}, 100)
	if err == nil {
		t.Fatal("retention override extended the default")
	}
}
