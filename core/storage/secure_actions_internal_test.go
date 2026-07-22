package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
)

func TestSecureActionSchemaIdempotencyAndOneTimeConsumption(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "actions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	columns, err := database.db.QueryContext(ctx, `PRAGMA table_info(secure_actions)`)
	if err != nil {
		t.Fatal(err)
	}
	operationColumn := false
	for columns.Next() {
		var ordinal, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := columns.Scan(&ordinal, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		operationColumn = operationColumn || name == "operation_id"
	}
	_ = columns.Close()
	if !operationColumn {
		t.Fatal("secure_actions.operation_id migration was not applied")
	}
	var auditEventTable int
	if err := database.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'secure_action_audit_events'
	`).Scan(&auditEventTable); err != nil || auditEventTable != 1 {
		t.Fatalf("secure action audit table: count=%d err=%v", auditEventTable, err)
	}

	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	requestJSON := json.RawMessage(`{"id":"action-1","operationId":"operation-1"}`)
	record := SecureActionRecord{
		ID: "action-1", RequestID: "action-1", ApplicationID: "application-1", OperationID: "operation-1",
		Decision: "HOLD", RequestJSON: requestJSON, DecisionJSON: json.RawMessage(`{"decision":"HOLD"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	firstAudit := storageAuditEntry("audit-action-create", "hash-action-create", "")
	if err := CommitAuditedMutation(ctx, database.CreateSecureActionMutation(record), firstAudit); err != nil {
		t.Fatal(err)
	}
	stored, err := database.GetSecureActionByOperationID(ctx, "operation-1")
	if err != nil || stored.ID != record.ID || !stored.RequestMatches(requestJSON) {
		t.Fatalf("stored action = %+v err=%v", stored, err)
	}
	conflict := record
	conflict.ID, conflict.RequestID = "action-2", "action-2"
	if err := CommitAuditedMutation(ctx, database.CreateSecureActionMutation(conflict), storageAuditEntry("audit-conflict", "hash-conflict", firstAudit.EntryHash)); err == nil {
		t.Fatal("duplicate operation id was accepted")
	}

	expiresAt := now.Add(time.Minute)
	record.Decision = "ALLOW_ONCE"
	record.DecisionJSON = json.RawMessage(`{"decision":"ALLOW_ONCE"}`)
	record.BypassExpiresAt = &expiresAt
	record.UpdatedAt = now.Add(time.Second)
	secondAudit := storageAuditEntry("audit-action-authorize", "hash-action-authorize", firstAudit.EntryHash)
	if err := CommitAuditedMutation(ctx, database.UpdateSecureActionMutation(record), secondAudit); err != nil {
		t.Fatal(err)
	}
	thirdAudit := storageAuditEntry("audit-action-consume", "hash-action-consume", secondAudit.EntryHash)
	firstLifecycleDigest := sha256.Sum256([]byte("first lifecycle request"))
	if err := CommitAuditedMutation(ctx, database.AppendSecureActionLifecycleMutation(
		"event-consume-1", record.ID, "SDK_ACTION_EXECUTION_STARTED", firstLifecycleDigest[:], now.Add(2*time.Second), now.Add(2*time.Second),
	), thirdAudit); err != nil {
		t.Fatal(err)
	}
	if lifecycle, err := database.GetSecureActionAuditEvent(ctx, "event-consume-1"); err != nil || lifecycle.ActionID != record.ID || !bytes.Equal(lifecycle.RequestDigest, firstLifecycleDigest[:]) {
		t.Fatalf("lifecycle event = %#v err=%v", lifecycle, err)
	}
	secondLifecycleDigest := sha256.Sum256([]byte("second lifecycle request"))
	if err := CommitAuditedMutation(ctx, database.AppendSecureActionLifecycleMutation(
		"event-consume-2", record.ID, "SDK_ACTION_EXECUTION_STARTED", secondLifecycleDigest[:], now.Add(3*time.Second), now.Add(3*time.Second),
	), storageAuditEntry("audit-action-reconsume", "hash-action-reconsume", thirdAudit.EntryHash)); !errors.Is(err, ErrOneTimeGrantConsumed) {
		t.Fatalf("second one-time consumption error = %v", err)
	}
	head, err := database.GetAuditHead(ctx)
	if err != nil || head.Count != 3 || head.Hash != thirdAudit.EntryHash {
		t.Fatalf("audit head after secure action lifecycle = %+v err=%v", head, err)
	}
}

func storageAuditEntry(id, hash, previous string) model.AuditEntry {
	return model.AuditEntry{
		ID: id, KeyID: "audit:test", OccurredAt: time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC),
		ActorType: "test", ActorID: "test-actor", Action: "test.action",
		ResourceType: "secure_action", ResourceID: "action-1", Outcome: "success",
		Details: json.RawMessage(`{}`), PreviousHash: previous, EntryHash: hash, Signature: "test-signature",
	}
}
