package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
)

var (
	ErrSecureActionNotFound      = errors.New("secure action not found")
	ErrSecureActionConflict      = errors.New("secure action id was reused with different input")
	ErrSecureActionAuditConflict = errors.New("secure action audit event id was reused with different input")
	ErrOneTimeGrantConsumed      = errors.New("one-time authorization was already consumed or expired")
	ErrInvalidActionLifecycle    = errors.New("secure action lifecycle transition is invalid")
)

// SecureActionRecord is the durable transport-neutral state for a protected
// application action. RequestJSON and DecisionJSON are canonical JSON; callers
// must never place application payloads or bearer credentials in either field.
type SecureActionRecord struct {
	ID              string
	RequestID       string
	ApplicationID   string
	OperationID     string
	Decision        string
	RequestJSON     []byte
	DecisionJSON    []byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ReleasedAt      *time.Time
	BypassExpiresAt *time.Time
}

func (database *DB) GetSecureAction(ctx context.Context, id string) (SecureActionRecord, error) {
	return scanSecureAction(database.db.QueryRowContext(ctx, `
		SELECT id, request_id, application_id, operation_id, decision, request_json, decision_json,
		       created_at, updated_at, released_at, bypass_expires_at
		FROM secure_actions WHERE id = ?
	`, id))
}

func (database *DB) GetSecureActionByRequestID(ctx context.Context, requestID string) (SecureActionRecord, error) {
	return scanSecureAction(database.db.QueryRowContext(ctx, `
		SELECT id, request_id, application_id, operation_id, decision, request_json, decision_json,
		       created_at, updated_at, released_at, bypass_expires_at
		FROM secure_actions WHERE request_id = ?
	`, requestID))
}

func (database *DB) GetSecureActionByOperationID(ctx context.Context, operationID string) (SecureActionRecord, error) {
	return scanSecureAction(database.db.QueryRowContext(ctx, `
		SELECT id, request_id, application_id, operation_id, decision, request_json, decision_json,
		       created_at, updated_at, released_at, bypass_expires_at
		FROM secure_actions WHERE operation_id = ?
	`, operationID))
}

func (database *DB) ListSecureActions(ctx context.Context, decision string, limit int) ([]SecureActionRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	query := `
		SELECT id, request_id, application_id, operation_id, decision, request_json, decision_json,
		       created_at, updated_at, released_at, bypass_expires_at
		FROM secure_actions`
	arguments := make([]any, 0, 2)
	if decision != "" {
		query += ` WHERE decision = ?`
		arguments = append(arguments, decision)
	}
	query += ` ORDER BY updated_at DESC, id ASC LIMIT ?`
	arguments = append(arguments, limit)
	rows, err := database.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list secure actions: %w", err)
	}
	defer rows.Close()
	result := make([]SecureActionRecord, 0)
	for rows.Next() {
		record, scanErr := scanSecureAction(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secure actions: %w", err)
	}
	return result, nil
}

func (database *DB) CountSecureActionsByDecision(ctx context.Context, decision string) (int, error) {
	var count int
	if err := database.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secure_actions WHERE decision = ?`, decision).Scan(&count); err != nil {
		return 0, fmt.Errorf("count secure actions: %w", err)
	}
	return count, nil
}

// CreateSecureActionWithAudit commits the initial decision and its signed audit
// entry in one SQLite transaction.
func (database *DB) CreateSecureActionWithAudit(ctx context.Context, record SecureActionRecord, entry model.AuditEntry) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secure action creation: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO secure_actions(
			id, request_id, application_id, operation_id, decision, request_json, decision_json,
			created_at, updated_at, released_at, bypass_expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, record.ID, record.RequestID, record.ApplicationID, record.OperationID, record.Decision,
		string(record.RequestJSON), string(record.DecisionJSON), formatTime(record.CreatedAt),
		formatTime(record.UpdatedAt), nullableTime(record.ReleasedAt), nullableTime(record.BypassExpiresAt))
	if err != nil {
		return fmt.Errorf("create secure action: %w", err)
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secure action creation: %w", err)
	}
	return nil
}

// CompareAndSwapSecureActionWithAudit replaces only the decision projection
// and lifecycle timestamps when every mutable field still matches the record
// the caller read. The audit entry is committed in the same transaction. This
// prevents a delayed evaluator or authorizer from clearing a consumed grant.
func (database *DB) CompareAndSwapSecureActionWithAudit(ctx context.Context, expected, next SecureActionRecord, entry model.AuditEntry) error {
	if expected.ID != next.ID || !expected.RequestMatches(next.RequestJSON) {
		return ErrSecureActionConflict
	}
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secure action update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE secure_actions SET
			decision = ?, decision_json = ?, updated_at = ?, released_at = ?, bypass_expires_at = ?
		WHERE id = ? AND request_json = ?
		  AND decision = ? AND decision_json = ? AND updated_at = ?
		  AND released_at IS ? AND bypass_expires_at IS ?
		  AND NOT EXISTS (
			SELECT 1 FROM secure_action_audit_events
			WHERE action_id = ? AND lifecycle = 'SDK_ACTION_EXECUTION_STARTED'
		  )
	`, next.Decision, string(next.DecisionJSON), formatTime(next.UpdatedAt),
		nullableTime(next.ReleasedAt), nullableTime(next.BypassExpiresAt), expected.ID,
		string(expected.RequestJSON), expected.Decision, string(expected.DecisionJSON), formatTime(expected.UpdatedAt),
		nullableTime(expected.ReleasedAt), nullableTime(expected.BypassExpiresAt), expected.ID)
	if err != nil {
		return fmt.Errorf("update secure action: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read secure action update count: %w", err)
	}
	if count != 1 {
		return ErrSecureActionConflict
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secure action update: %w", err)
	}
	return nil
}

// RequestMatches reports whether a retry is byte-for-byte identical to the
// canonical request already committed for this action.
func (record SecureActionRecord) RequestMatches(canonical []byte) bool {
	return bytes.Equal(record.RequestJSON, canonical)
}

type SecureActionAuditEventRecord struct {
	ActionID      string
	RequestDigest []byte
}

type SecureActionExecutionState struct {
	Started  bool
	Terminal string
}

func (database *DB) GetSecureActionExecutionState(ctx context.Context, actionID string) (SecureActionExecutionState, error) {
	rows, err := database.db.QueryContext(ctx, `
		SELECT lifecycle FROM secure_action_audit_events
		WHERE action_id = ? AND lifecycle IN (
			'SDK_ACTION_EXECUTION_STARTED',
			'SDK_ACTION_EXECUTION_SUCCEEDED',
			'SDK_ACTION_EXECUTION_FAILED'
		)
		ORDER BY occurred_at, event_id
	`, actionID)
	if err != nil {
		return SecureActionExecutionState{}, fmt.Errorf("read secure action execution state: %w", err)
	}
	defer rows.Close()
	var state SecureActionExecutionState
	for rows.Next() {
		var lifecycle string
		if err := rows.Scan(&lifecycle); err != nil {
			return SecureActionExecutionState{}, fmt.Errorf("scan secure action execution state: %w", err)
		}
		if lifecycle == "SDK_ACTION_EXECUTION_STARTED" {
			state.Started = true
		} else {
			state.Terminal = lifecycle
		}
	}
	if err := rows.Err(); err != nil {
		return SecureActionExecutionState{}, fmt.Errorf("iterate secure action execution state: %w", err)
	}
	return state, nil
}

func (database *DB) GetSecureActionAuditEvent(ctx context.Context, eventID string) (SecureActionAuditEventRecord, error) {
	var record SecureActionAuditEventRecord
	if err := database.db.QueryRowContext(ctx, `
		SELECT action_id, request_digest FROM secure_action_audit_events WHERE event_id = ?
	`, eventID).Scan(&record.ActionID, &record.RequestDigest); errors.Is(err, sql.ErrNoRows) {
		return SecureActionAuditEventRecord{}, ErrSecureActionNotFound
	} else if err != nil {
		return SecureActionAuditEventRecord{}, fmt.Errorf("read secure action audit event: %w", err)
	}
	return record, nil
}

// AppendSecureActionLifecycleWithAudit makes lifecycle event idempotency and
// one-time grant consumption part of the same transaction as the signed audit
// entry. The SDK_ACTION_EXECUTION_STARTED transition is the authoritative
// single-use boundary until a dedicated token-bearing consume call is added.
func (database *DB) AppendSecureActionLifecycleWithAudit(
	ctx context.Context,
	eventID string,
	expected SecureActionRecord,
	nodeID, lifecycle string,
	requestDigest []byte,
	occurredAt, now time.Time,
	entry model.AuditEntry,
) error {
	if len(requestDigest) != sha256.Size {
		return errors.New("secure action audit request digest must be SHA-256")
	}
	if expected.ID == "" || nodeID == "" {
		return ErrSecureActionConflict
	}
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secure action lifecycle: %w", err)
	}
	defer tx.Rollback()
	var decision string
	var releasedAt, bypassExpiresAt sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT decision, released_at, bypass_expires_at FROM secure_actions WHERE id = ?
	`, expected.ID).Scan(&decision, &releasedAt, &bypassExpiresAt); errors.Is(err, sql.ErrNoRows) {
		return ErrSecureActionNotFound
	} else if err != nil {
		return fmt.Errorf("read secure action lifecycle state: %w", err)
	}
	if lifecycle == "SDK_ACTION_EXECUTION_STARTED" || lifecycle == "SDK_ACTION_EXECUTION_SUCCEEDED" || lifecycle == "SDK_ACTION_EXECUTION_FAILED" {
		if decision != "ALLOW" && decision != "ALLOW_ONCE" {
			return ErrInvalidActionLifecycle
		}
		rows, queryErr := tx.QueryContext(ctx, `
			SELECT lifecycle, occurred_at FROM secure_action_audit_events
			WHERE action_id = ? AND lifecycle IN (
				'SDK_ACTION_EXECUTION_STARTED',
				'SDK_ACTION_EXECUTION_SUCCEEDED',
				'SDK_ACTION_EXECUTION_FAILED'
			)
		`, expected.ID)
		if queryErr != nil {
			return fmt.Errorf("read secure action execution history: %w", queryErr)
		}
		starts, terminals := 0, 0
		var startedAt time.Time
		for rows.Next() {
			var priorLifecycle, priorOccurredAt string
			if scanErr := rows.Scan(&priorLifecycle, &priorOccurredAt); scanErr != nil {
				rows.Close()
				return fmt.Errorf("scan secure action execution history: %w", scanErr)
			}
			if priorLifecycle == "SDK_ACTION_EXECUTION_STARTED" {
				starts++
				startedAt, queryErr = parseTime(priorOccurredAt)
				if queryErr != nil {
					rows.Close()
					return fmt.Errorf("parse secure action execution start: %w", queryErr)
				}
			} else {
				terminals++
			}
		}
		if queryErr = rows.Err(); queryErr != nil {
			rows.Close()
			return fmt.Errorf("iterate secure action execution history: %w", queryErr)
		}
		rows.Close()
		if lifecycle == "SDK_ACTION_EXECUTION_STARTED" {
			if starts != 0 || terminals != 0 {
				return ErrInvalidActionLifecycle
			}
		} else if starts != 1 || terminals != 0 || occurredAt.Before(startedAt) {
			return ErrInvalidActionLifecycle
		}
	}
	var insertResult sql.Result
	if lifecycle == "SDK_ACTION_EXECUTION_STARTED" {
		insertResult, err = tx.ExecContext(ctx, `
			INSERT INTO secure_action_audit_events(event_id, action_id, lifecycle, occurred_at, request_digest)
			SELECT ?, action.id, ?, ?, ?
			FROM secure_actions AS action
			JOIN nodes AS node ON node.id = ? AND node.status = 'ACTIVE'
			WHERE action.id = ? AND action.decision = ? AND action.decision_json = ? AND action.updated_at = ?
			  AND action.released_at IS ? AND action.bypass_expires_at IS ?
		`, eventID, lifecycle, formatTime(occurredAt), requestDigest, nodeID, expected.ID,
			expected.Decision, string(expected.DecisionJSON), formatTime(expected.UpdatedAt),
			nullableTime(expected.ReleasedAt), nullableTime(expected.BypassExpiresAt))
	} else {
		insertResult, err = tx.ExecContext(ctx, `
			INSERT INTO secure_action_audit_events(event_id, action_id, lifecycle, occurred_at, request_digest)
			SELECT ?, action.id, ?, ?, ?
			FROM secure_actions AS action
			WHERE action.id = ? AND action.decision = ? AND action.decision_json = ? AND action.updated_at = ?
			  AND action.released_at IS ? AND action.bypass_expires_at IS ?
		`, eventID, lifecycle, formatTime(occurredAt), requestDigest, expected.ID,
			expected.Decision, string(expected.DecisionJSON), formatTime(expected.UpdatedAt),
			nullableTime(expected.ReleasedAt), nullableTime(expected.BypassExpiresAt))
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrInvalidActionLifecycle
		}
		return fmt.Errorf("record secure action audit event: %w", err)
	}
	inserted, err := insertResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect secure action audit insertion: %w", err)
	}
	if inserted != 1 {
		return ErrSecureActionConflict
	}
	if lifecycle == "SDK_ACTION_EXECUTION_STARTED" {
		switch decision {
		case "ALLOW":
			// Ordinary allows are not single-use grants.
		case "ALLOW_ONCE":
			if releasedAt.Valid || !bypassExpiresAt.Valid {
				return ErrOneTimeGrantConsumed
			}
			expiry, parseErr := parseTime(bypassExpiresAt.String)
			if parseErr != nil || !now.Before(expiry) {
				return ErrOneTimeGrantConsumed
			}
			result, updateErr := tx.ExecContext(ctx, `
				UPDATE secure_actions SET released_at = ?, updated_at = ?
				WHERE id = ? AND released_at IS NULL
			`, formatTime(now), formatTime(now), expected.ID)
			if updateErr != nil {
				return fmt.Errorf("consume one-time authorization: %w", updateErr)
			}
			count, countErr := result.RowsAffected()
			if countErr != nil || count != 1 {
				return ErrOneTimeGrantConsumed
			}
		default:
			return ErrOneTimeGrantConsumed
		}
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secure action lifecycle: %w", err)
	}
	return nil
}

type secureActionScanner interface {
	Scan(dest ...any) error
}

func scanSecureAction(row secureActionScanner) (SecureActionRecord, error) {
	var record SecureActionRecord
	var requestJSON, decisionJSON, createdAt, updatedAt string
	var releasedAt, bypassExpiresAt sql.NullString
	if err := row.Scan(
		&record.ID, &record.RequestID, &record.ApplicationID, &record.OperationID, &record.Decision,
		&requestJSON, &decisionJSON, &createdAt, &updatedAt, &releasedAt, &bypassExpiresAt,
	); errors.Is(err, sql.ErrNoRows) {
		return SecureActionRecord{}, ErrSecureActionNotFound
	} else if err != nil {
		return SecureActionRecord{}, fmt.Errorf("scan secure action: %w", err)
	}
	record.RequestJSON = []byte(requestJSON)
	record.DecisionJSON = []byte(decisionJSON)
	var err error
	if record.CreatedAt, err = parseTime(createdAt); err != nil {
		return SecureActionRecord{}, fmt.Errorf("parse secure action creation time: %w", err)
	}
	if record.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return SecureActionRecord{}, fmt.Errorf("parse secure action update time: %w", err)
	}
	if releasedAt.Valid {
		value, parseErr := parseTime(releasedAt.String)
		if parseErr != nil {
			return SecureActionRecord{}, fmt.Errorf("parse secure action release time: %w", parseErr)
		}
		record.ReleasedAt = &value
	}
	if bypassExpiresAt.Valid {
		value, parseErr := parseTime(bypassExpiresAt.String)
		if parseErr != nil {
			return SecureActionRecord{}, fmt.Errorf("parse secure action bypass expiry: %w", parseErr)
		}
		record.BypassExpiresAt = &value
	}
	return record, nil
}
