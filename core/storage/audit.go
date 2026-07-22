package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DBarr3/AntiFlock/internal/model"
)

var (
	ErrAuditHeadConflict       = errors.New("audit head changed concurrently")
	ErrAuditedMutationRequired = errors.New("a storage-issued audited mutation is required")
)

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type AuditHead struct {
	Count    uint64
	Sequence uint64
	Hash     string
}

func (database *DB) GetAuditHead(ctx context.Context) (AuditHead, error) {
	var head AuditHead
	var actual AuditHead
	if err := database.db.QueryRowContext(ctx, `
		SELECT state.entry_count, state.sequence, state.head_hash,
		       (SELECT COUNT(*) FROM audit_entries),
		       COALESCE((SELECT MAX(sequence) FROM audit_entries), 0),
		       COALESCE((SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1), '')
		FROM audit_state AS state WHERE state.id = 1
	`).Scan(&head.Count, &head.Sequence, &head.Hash, &actual.Count, &actual.Sequence, &actual.Hash); err != nil {
		return AuditHead{}, fmt.Errorf("read atomic audit state: %w", err)
	}
	if actual != head {
		return AuditHead{}, fmt.Errorf("audit state diverges from entries: state=%+v entries=%+v", head, actual)
	}
	return head, nil
}

func (database *DB) LastAuditHash(ctx context.Context) (string, error) {
	head, err := database.GetAuditHead(ctx)
	if err != nil {
		return "", err
	}
	return head.Hash, nil
}

func (database *DB) InsertAuditEntry(ctx context.Context, entry model.AuditEntry) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit insert: %w", err)
	}
	defer tx.Rollback()
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit insert: %w", err)
	}
	return nil
}

func insertAuditEntry(ctx context.Context, executor contextExecer, entry model.AuditEntry) error {
	if entry.KeyID == "" {
		return errors.New("audit entry key id is required")
	}
	if len(entry.Details) == 0 {
		entry.Details = json.RawMessage(`{}`)
	}
	result, err := executor.ExecContext(ctx, `
		INSERT INTO audit_entries(
			id, key_id, occurred_at, actor_type, actor_id, action, resource_type, resource_id,
			outcome, details_json, previous_hash, entry_hash, signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, entry.ID, entry.KeyID, formatTime(entry.OccurredAt), entry.ActorType, entry.ActorID, entry.Action,
		entry.ResourceType, entry.ResourceID, entry.Outcome, string(entry.Details),
		entry.PreviousHash, entry.EntryHash, entry.Signature)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read audit sequence: %w", err)
	}
	if sequence <= 0 {
		return errors.New("audit sequence must be positive")
	}
	result, err = executor.ExecContext(ctx, `
		UPDATE audit_state
		SET entry_count = entry_count + 1, sequence = ?, head_hash = ?
		WHERE id = 1 AND head_hash = ?
	`, sequence, entry.EntryHash, entry.PreviousHash)
	if err != nil {
		return fmt.Errorf("advance audit state: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read audit state update count: %w", err)
	}
	if updated != 1 {
		return ErrAuditHeadConflict
	}
	return nil
}

func (database *DB) ListAuditEntries(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	return database.ListAuditEntriesAfter(ctx, 0, limit)
}

func (database *DB) ListAuditEntriesAfter(ctx context.Context, afterSequence uint64, limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := database.db.QueryContext(ctx, `
		SELECT sequence, id, key_id, occurred_at, actor_type, actor_id, action, resource_type, resource_id,
		       outcome, details_json, previous_hash, entry_hash, signature
		FROM audit_entries WHERE sequence > ? ORDER BY sequence ASC LIMIT ?
	`, afterSequence, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()
	var result []model.AuditEntry
	for rows.Next() {
		var entry model.AuditEntry
		var occurredAt, details string
		if err := rows.Scan(&entry.Sequence, &entry.ID, &entry.KeyID, &occurredAt, &entry.ActorType, &entry.ActorID,
			&entry.Action, &entry.ResourceType, &entry.ResourceID, &entry.Outcome, &details,
			&entry.PreviousHash, &entry.EntryHash, &entry.Signature); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		var err error
		if entry.OccurredAt, err = parseTime(occurredAt); err != nil {
			return nil, fmt.Errorf("parse audit entry time: %w", err)
		}
		entry.Details = json.RawMessage(details)
		result = append(result, entry)
	}
	return result, rows.Err()
}
