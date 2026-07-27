package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NanoCursorRecord is the durable scheduling state for one admitted Nano
// watchdog program on one active node. It contains no program source or input.
type NanoCursorRecord struct {
	Initialized bool
	NextDueUnix int64
}

func (database *DB) LoadNanoCursor(ctx context.Context, programDigest, nodeID string) (NanoCursorRecord, error) {
	if !boundedNanoCursorID(programDigest, 128) || !boundedNanoCursorID(nodeID, 128) {
		return NanoCursorRecord{}, errors.New("nano cursor identity is invalid")
	}
	var initialized int
	var record NanoCursorRecord
	err := database.db.QueryRowContext(ctx, `SELECT initialized, next_due_unix FROM nano_runner_cursors WHERE program_digest = ? AND node_id = ?`, programDigest, nodeID).Scan(&initialized, &record.NextDueUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return NanoCursorRecord{}, nil
	}
	if err != nil {
		return NanoCursorRecord{}, fmt.Errorf("read nano cursor: %w", err)
	}
	if initialized != 0 && initialized != 1 {
		return NanoCursorRecord{}, errors.New("nano cursor state is invalid")
	}
	record.Initialized = initialized == 1
	return record, nil
}

func (database *DB) SaveNanoCursor(ctx context.Context, programDigest, nodeID string, record NanoCursorRecord, now time.Time) error {
	if !boundedNanoCursorID(programDigest, 128) || !boundedNanoCursorID(nodeID, 128) || now.IsZero() {
		return errors.New("nano cursor state is invalid")
	}
	initialized := 0
	if record.Initialized {
		initialized = 1
	}
	_, err := database.db.ExecContext(ctx, `
		INSERT INTO nano_runner_cursors(program_digest, node_id, initialized, next_due_unix, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(program_digest, node_id) DO UPDATE SET initialized = excluded.initialized, next_due_unix = excluded.next_due_unix, updated_at = excluded.updated_at
	`, programDigest, nodeID, initialized, record.NextDueUnix, formatTime(now))
	if err != nil {
		return fmt.Errorf("save nano cursor: %w", err)
	}
	return nil
}

// CompareAndSwapNanoCursor advances a cursor only if it still equals the
// evaluation input. This prevents concurrent Core requests from both exposing
// a proposal for one schedule tick.
func (database *DB) CompareAndSwapNanoCursor(ctx context.Context, programDigest, nodeID string, previous, next NanoCursorRecord, now time.Time) (bool, error) {
	if !boundedNanoCursorID(programDigest, 128) || !boundedNanoCursorID(nodeID, 128) || now.IsZero() {
		return false, errors.New("nano cursor state is invalid")
	}
	previousInitialized, nextInitialized := 0, 0
	if previous.Initialized {
		previousInitialized = 1
	}
	if next.Initialized {
		nextInitialized = 1
	}
	updatedAt := formatTime(now)
	result, err := database.db.ExecContext(ctx, `
		UPDATE nano_runner_cursors
		SET initialized = ?, next_due_unix = ?, updated_at = ?
		WHERE program_digest = ? AND node_id = ? AND initialized = ? AND next_due_unix = ?
	`, nextInitialized, next.NextDueUnix, updatedAt, programDigest, nodeID, previousInitialized, previous.NextDueUnix)
	if err != nil {
		return false, fmt.Errorf("compare nano cursor: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect nano cursor compare: %w", err)
	}
	if changed == 1 {
		return true, nil
	}
	if previous.Initialized || previous.NextDueUnix != 0 {
		return false, nil
	}
	result, err = database.db.ExecContext(ctx, `
		INSERT INTO nano_runner_cursors(program_digest, node_id, initialized, next_due_unix, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(program_digest, node_id) DO NOTHING
	`, programDigest, nodeID, nextInitialized, next.NextDueUnix, updatedAt)
	if err != nil {
		return false, fmt.Errorf("create nano cursor: %w", err)
	}
	changed, err = result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect nano cursor creation: %w", err)
	}
	return changed == 1, nil
}

func boundedNanoCursorID(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
