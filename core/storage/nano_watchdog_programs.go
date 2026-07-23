package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
)

type NanoWatchdogStatus string

const (
	NanoWatchdogAdmitted NanoWatchdogStatus = "ADMITTED"
	NanoWatchdogDisabled NanoWatchdogStatus = "DISABLED"
)

// NanoWatchdogProgramRecord preserves the reviewed source and its canonical
// digest. It never stores a finding frame, provider secret, or proposed action.
type NanoWatchdogProgramRecord struct {
	ID string
	NodeID string
	Name string
	Source string
	ProgramDigest string
	BindingID string
	Status NanoWatchdogStatus
	OperationID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (database *DB) CreateNanoWatchdogProgramWithAudit(ctx context.Context, record NanoWatchdogProgramRecord, entry model.AuditEntry) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil { return fmt.Errorf("begin watchdog program admission: %w", err) }
	defer tx.Rollback()
	if err := createNanoWatchdogProgram(ctx, tx, record); err != nil { return err }
	if err := insertAuditEntry(ctx, tx, entry); err != nil { return err }
	if err := tx.Commit(); err != nil { return fmt.Errorf("commit watchdog program admission: %w", err) }
	return nil
}

func createNanoWatchdogProgram(ctx context.Context, executor contextExecer, record NanoWatchdogProgramRecord) error {
	if !validNanoWatchdogRecord(record) { return errors.New("watchdog program record is invalid") }
	_, err := executor.ExecContext(ctx, `
		INSERT INTO nano_watchdog_programs(id, node_id, name, source, program_digest, binding_id, status, operation_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, record.ID, record.NodeID, record.Name, record.Source, record.ProgramDigest, record.BindingID, record.Status, record.OperationID, formatTime(record.CreatedAt), formatTime(record.UpdatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: nano_watchdog_programs.operation_id") { return ErrOperationConflict }
		return fmt.Errorf("create watchdog program: %w", err)
	}
	return nil
}

func (database *DB) GetNanoWatchdogProgram(ctx context.Context, id string) (NanoWatchdogProgramRecord, error) {
	if !boundedNanoCursorID(id, 128) { return NanoWatchdogProgramRecord{}, ErrNodeNotFound }
	return scanNanoWatchdogProgram(database.db.QueryRowContext(ctx, `
		SELECT id, node_id, name, source, program_digest, binding_id, status, operation_id, created_at, updated_at
		FROM nano_watchdog_programs WHERE id = ?`, id))
}


func (database *DB) GetNanoWatchdogProgramByOperation(ctx context.Context, operationID string) (NanoWatchdogProgramRecord, error) {
	if !boundedNanoCursorID(operationID, 128) { return NanoWatchdogProgramRecord{}, ErrNodeNotFound }
	return scanNanoWatchdogProgram(database.db.QueryRowContext(ctx, `
		SELECT id, node_id, name, source, program_digest, binding_id, status, operation_id, created_at, updated_at
		FROM nano_watchdog_programs WHERE operation_id = ?`, operationID))
}

func (database *DB) ListNanoWatchdogPrograms(ctx context.Context, nodeID string) ([]NanoWatchdogProgramRecord, error) {
	if !boundedNanoCursorID(nodeID, 128) { return nil, errors.New("watchdog node id is invalid") }
	rows, err := database.db.QueryContext(ctx, `
		SELECT id, node_id, name, source, program_digest, binding_id, status, operation_id, created_at, updated_at
		FROM nano_watchdog_programs WHERE node_id = ? ORDER BY updated_at DESC, id`, nodeID)
	if err != nil { return nil, fmt.Errorf("list watchdog programs: %w", err) }
	defer rows.Close()
	result := make([]NanoWatchdogProgramRecord, 0)
	for rows.Next() { record, scanErr := scanNanoWatchdogProgram(rows); if scanErr != nil { return nil, scanErr }; result = append(result, record) }
	return result, rows.Err()
}

func scanNanoWatchdogProgram(row rowScanner) (NanoWatchdogProgramRecord, error) {
	var record NanoWatchdogProgramRecord; var created, updated string
	err := row.Scan(&record.ID, &record.NodeID, &record.Name, &record.Source, &record.ProgramDigest, &record.BindingID, &record.Status, &record.OperationID, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) { return NanoWatchdogProgramRecord{}, ErrNodeNotFound }
	if err != nil { return NanoWatchdogProgramRecord{}, fmt.Errorf("scan watchdog program: %w", err) }
	var parseErr error
	if record.CreatedAt, parseErr = parseTime(created); parseErr != nil { return NanoWatchdogProgramRecord{}, errors.New("watchdog program creation time is invalid") }
	if record.UpdatedAt, parseErr = parseTime(updated); parseErr != nil { return NanoWatchdogProgramRecord{}, errors.New("watchdog program update time is invalid") }
	if !validNanoWatchdogRecord(record) { return NanoWatchdogProgramRecord{}, errors.New("watchdog program state is invalid") }
	return record, nil
}

func validNanoWatchdogRecord(record NanoWatchdogProgramRecord) bool {
	return boundedNanoCursorID(record.ID, 128) && boundedNanoCursorID(record.NodeID, 128) && boundedNanoCursorID(record.Name, 128) &&
		len(record.Source) > 0 && len(record.Source) <= 64<<10 && boundedNanoCursorID(record.ProgramDigest, 128) && boundedNanoCursorID(record.BindingID, 128) &&
		(record.Status == NanoWatchdogAdmitted || record.Status == NanoWatchdogDisabled) && boundedNanoCursorID(record.OperationID, 128) && !record.CreatedAt.IsZero() && !record.UpdatedAt.IsZero()
}
