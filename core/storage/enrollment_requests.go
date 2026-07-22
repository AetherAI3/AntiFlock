package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
)

var (
	ErrEnrollmentRequestNotFound = errors.New("enrollment request not found")
	ErrEnrollmentRequestDecided  = errors.New("enrollment request has already been decided")
	ErrEnrollmentRequestExpired  = errors.New("enrollment request has expired")
	ErrCredentialReused          = errors.New("node credential has already been admitted or proposed")
	ErrNodeIdentityUsed          = errors.New("node identity has already been admitted or proposed")
)

type EnrollmentRequestRecord struct {
	ID                   string
	TokenID              string
	RequestID            string
	RequestDigest        []byte
	Status               string
	ProposedNodeID       string
	DisplayName          string
	NodeType             string
	Platform             string
	PlatformVersion      string
	PublicKey            []byte
	CapabilitiesJSON     json.RawMessage
	AllowedTags          []string
	RequestedAt          time.Time
	ExpiresAt            time.Time
	DecisionReasonCode   string
	DecisionOperationID  string
	DecidedByPrincipalID string
	DecidedAt            *time.Time
	ApprovedTags         []string
	NodeID               string
}

func (database *DB) SubmitEnrollmentRequestWithAudit(
	ctx context.Context,
	tokenHash []byte,
	now time.Time,
	record EnrollmentRequestRecord,
	entry model.AuditEntry,
) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment request submission: %w", err)
	}
	defer tx.Rollback()
	var tokenID, expiresAt string
	var consumedAt sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT id, expires_at, consumed_at FROM enrollment_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&tokenID, &expiresAt, &consumedAt); errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentTokenInvalid
	} else if err != nil {
		return fmt.Errorf("read enrollment token for submission: %w", err)
	}
	if consumedAt.Valid {
		return ErrEnrollmentTokenUsed
	}
	expiry, err := parseTime(expiresAt)
	if err != nil {
		return fmt.Errorf("parse enrollment token expiry: %w", err)
	}
	if !now.Before(expiry) {
		return ErrEnrollmentTokenExpired
	}
	var keyUses int
	if err := tx.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM nodes WHERE public_key = ?) +
		       (SELECT COUNT(*) FROM enrollment_requests WHERE public_key = ?)
	`, record.PublicKey, record.PublicKey).Scan(&keyUses); err != nil {
		return fmt.Errorf("check credential history: %w", err)
	}
	if keyUses != 0 {
		return ErrCredentialReused
	}
	if err := claimNodeIdentity(ctx, tx, record.ProposedNodeID, record.ID, now); err != nil {
		return err
	}
	record.TokenID = tokenID
	record.ExpiresAt = expiry
	allowedTags, err := json.Marshal(record.AllowedTags)
	if err != nil {
		return fmt.Errorf("encode allowed enrollment tags: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO enrollment_requests(
			id, token_id, request_id, request_digest, status, proposed_node_id, display_name,
			node_type, platform, platform_version, public_key, capabilities_json, allowed_tags_json, requested_at, expires_at
		) VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, record.ID, record.TokenID, record.RequestID, record.RequestDigest, record.ProposedNodeID,
		record.DisplayName, record.NodeType, record.Platform, record.PlatformVersion, record.PublicKey,
		string(record.CapabilitiesJSON), string(allowedTags), formatTime(record.RequestedAt), formatTime(record.ExpiresAt)); err != nil {
		return fmt.Errorf("insert enrollment request: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE enrollment_tokens
		SET consumed_at = ?, consumed_by_node_id = ?, consumed_request_id = ?, consumed_request_digest = ?
		WHERE token_hash = ? AND consumed_at IS NULL
	`, formatTime(now), record.ProposedNodeID, record.RequestID, record.RequestDigest, tokenHash)
	if err != nil {
		return fmt.Errorf("reserve enrollment token: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrEnrollmentTokenUsed
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment request submission: %w", err)
	}
	return nil
}

func (database *DB) ResolveEnrollmentRequestReplay(ctx context.Context, tokenHash []byte, requestID string, requestDigest []byte) (EnrollmentRequestRecord, error) {
	record, err := database.GetEnrollmentToken(ctx, tokenHash, time.Time{})
	if err != nil {
		return EnrollmentRequestRecord{}, err
	}
	if record.ConsumedAt == nil || record.ConsumedRequestID != requestID || !constantBytesEqual(record.ConsumedRequestDigest, requestDigest) {
		return EnrollmentRequestRecord{}, ErrEnrollmentTokenUsed
	}
	return database.GetEnrollmentRequestByToken(ctx, record.ID)
}

func (database *DB) GetEnrollmentRequest(ctx context.Context, id string) (EnrollmentRequestRecord, error) {
	return scanEnrollmentRequest(database.db.QueryRowContext(ctx, enrollmentRequestSelect+` WHERE id = ?`, id))
}

func (database *DB) GetEnrollmentRequestByToken(ctx context.Context, tokenID string) (EnrollmentRequestRecord, error) {
	return scanEnrollmentRequest(database.db.QueryRowContext(ctx, enrollmentRequestSelect+` WHERE token_id = ?`, tokenID))
}

const enrollmentRequestSelect = `
	SELECT id, token_id, request_id, request_digest, status, proposed_node_id, display_name,
	       node_type, platform, platform_version, public_key, capabilities_json, allowed_tags_json, requested_at,
	       expires_at, COALESCE(decision_reason_code, ''), COALESCE(decision_operation_id, ''),
	       COALESCE(decided_by_principal_id, ''), decided_at, COALESCE(approved_tags_json, '[]'),
	       COALESCE(node_id, '')
	FROM enrollment_requests`

func scanEnrollmentRequest(row rowScanner) (EnrollmentRequestRecord, error) {
	var record EnrollmentRequestRecord
	var capabilities, allowedTags, requestedAt, expiresAt, approvedTags string
	var decidedAt sql.NullString
	if err := row.Scan(
		&record.ID, &record.TokenID, &record.RequestID, &record.RequestDigest, &record.Status,
		&record.ProposedNodeID, &record.DisplayName, &record.NodeType, &record.Platform,
		&record.PlatformVersion, &record.PublicKey, &capabilities, &allowedTags, &requestedAt, &expiresAt,
		&record.DecisionReasonCode, &record.DecisionOperationID, &record.DecidedByPrincipalID,
		&decidedAt, &approvedTags, &record.NodeID,
	); errors.Is(err, sql.ErrNoRows) {
		return EnrollmentRequestRecord{}, ErrEnrollmentRequestNotFound
	} else if err != nil {
		return EnrollmentRequestRecord{}, fmt.Errorf("scan enrollment request: %w", err)
	}
	record.CapabilitiesJSON = json.RawMessage(capabilities)
	if err := json.Unmarshal([]byte(allowedTags), &record.AllowedTags); err != nil {
		return EnrollmentRequestRecord{}, fmt.Errorf("decode allowed enrollment tags: %w", err)
	}
	if err := json.Unmarshal([]byte(approvedTags), &record.ApprovedTags); err != nil {
		return EnrollmentRequestRecord{}, fmt.Errorf("decode approved enrollment tags: %w", err)
	}
	var err error
	if record.RequestedAt, err = parseTime(requestedAt); err != nil {
		return EnrollmentRequestRecord{}, fmt.Errorf("parse enrollment request time: %w", err)
	}
	if record.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return EnrollmentRequestRecord{}, fmt.Errorf("parse enrollment request expiry: %w", err)
	}
	if decidedAt.Valid {
		value, err := parseTime(decidedAt.String)
		if err != nil {
			return EnrollmentRequestRecord{}, fmt.Errorf("parse enrollment decision time: %w", err)
		}
		record.DecidedAt = &value
	}
	return record, nil
}

func (database *DB) ApproveEnrollmentRequestWithAudit(
	ctx context.Context,
	enrollmentID, actorID, operationID, reasonCode string,
	tags []string,
	now time.Time,
	node model.Node,
	entry model.AuditEntry,
) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment approval: %w", err)
	}
	defer tx.Rollback()
	var status, expiresAt string
	if err := tx.QueryRowContext(ctx, `SELECT status, expires_at FROM enrollment_requests WHERE id = ?`, enrollmentID).Scan(&status, &expiresAt); errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentRequestNotFound
	} else if err != nil {
		return fmt.Errorf("read enrollment request for approval: %w", err)
	}
	if status != "PENDING" {
		return ErrEnrollmentRequestDecided
	}
	expiry, err := parseTime(expiresAt)
	if err != nil {
		return fmt.Errorf("parse enrollment request expiry: %w", err)
	}
	if !now.Before(expiry) {
		if _, updateErr := tx.ExecContext(ctx, `UPDATE enrollment_requests SET status = 'EXPIRED' WHERE id = ? AND status = 'PENDING'`, enrollmentID); updateErr != nil {
			return fmt.Errorf("expire enrollment request: %w", updateErr)
		}
		return ErrEnrollmentRequestExpired
	}
	var identityOwner string
	if err := tx.QueryRowContext(ctx, `
		SELECT first_enrollment_id FROM node_identity_registry WHERE node_id = ?
	`, node.ID).Scan(&identityOwner); errors.Is(err, sql.ErrNoRows) {
		return ErrNodeIdentityUsed
	} else if err != nil {
		return fmt.Errorf("read enrolled node identity owner: %w", err)
	} else if identityOwner != enrollmentID {
		return ErrNodeIdentityUsed
	}
	if err := insertNode(ctx, tx, node); err != nil {
		return err
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("encode approved tags: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE enrollment_requests
		SET status = 'APPROVED', decision_reason_code = ?, decision_operation_id = ?,
		    decided_by_principal_id = ?, decided_at = ?, approved_tags_json = ?, node_id = ?
		WHERE id = ? AND status = 'PENDING'
	`, reasonCode, operationID, actorID, formatTime(now), string(tagsJSON), node.ID, enrollmentID); err != nil {
		return fmt.Errorf("approve enrollment request: %w", err)
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment approval: %w", err)
	}
	return nil
}

func claimNodeIdentity(ctx context.Context, executor contextExecer, nodeID, enrollmentID string, now time.Time) error {
	result, err := executor.ExecContext(ctx, `
		INSERT OR IGNORE INTO node_identity_registry(node_id, first_enrollment_id, claimed_at)
		VALUES (?, ?, ?)
	`, nodeID, enrollmentID, formatTime(now))
	if err != nil {
		return fmt.Errorf("claim node identity: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("read node identity claim result: %w", err)
	} else if count != 1 {
		return ErrNodeIdentityUsed
	}
	return nil
}

func (database *DB) DenyEnrollmentRequestWithAudit(
	ctx context.Context,
	enrollmentID, actorID, operationID, reasonCode string,
	now time.Time,
	entry model.AuditEntry,
) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment denial: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE enrollment_requests
		SET status = 'DENIED', decision_reason_code = ?, decision_operation_id = ?,
		    decided_by_principal_id = ?, decided_at = ?
		WHERE id = ? AND status = 'PENDING'
	`, reasonCode, operationID, actorID, formatTime(now), enrollmentID)
	if err != nil {
		return fmt.Errorf("deny enrollment request: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		var status string
		if readErr := tx.QueryRowContext(ctx, `SELECT status FROM enrollment_requests WHERE id = ?`, enrollmentID).Scan(&status); errors.Is(readErr, sql.ErrNoRows) {
			return ErrEnrollmentRequestNotFound
		}
		return ErrEnrollmentRequestDecided
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment denial: %w", err)
	}
	return nil
}

func insertNode(ctx context.Context, executor contextExecer, node model.Node) error {
	tags, err := json.Marshal(node.Tags)
	if err != nil {
		return fmt.Errorf("encode node tags: %w", err)
	}
	capabilities := node.Capabilities
	if len(capabilities) == 0 {
		capabilities = json.RawMessage(`{}`)
	}
	if _, err := executor.ExecContext(ctx, `
		INSERT INTO nodes(
			id, name, node_type, platform, platform_version, status, tags_json, capabilities_json,
			capabilities_verification, public_key, certificate_pem, enrolled_at, last_policy_revision
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, node.ID, node.Name, node.Type, node.Platform, node.PlatformVersion, node.Status,
		string(tags), string(capabilities), node.CapabilitiesVerification, node.PublicKey,
		node.CertificatePEM, formatTime(node.EnrolledAt), node.LastPolicyRevision); err != nil {
		return fmt.Errorf("insert enrolled node: %w", err)
	}
	return nil
}

func constantBytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
