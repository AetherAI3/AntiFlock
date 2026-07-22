package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
)

var (
	ErrEnrollmentTokenInvalid = errors.New("enrollment token is invalid")
	ErrEnrollmentTokenExpired = errors.New("enrollment token has expired")
	ErrEnrollmentTokenUsed    = errors.New("enrollment token has already been used")
	ErrNodeNotFound           = errors.New("node not found")
	ErrNodeRevoked            = errors.New("revoked node must be re-enrolled with new credentials")
	ErrOperationConflict      = errors.New("operation id has already been used")
)

type EnrollmentTokenRecord struct {
	ID                    string
	Hash                  []byte
	ScopeJSON             json.RawMessage
	CreatedByPrincipalID  string
	OperationID           string
	CreatedAt             time.Time
	ExpiresAt             time.Time
	ConsumedAt            *time.Time
	ConsumedByNodeID      string
	ConsumedRequestID     string
	ConsumedRequestDigest []byte
}

func (database *DB) CreateEnrollmentToken(ctx context.Context, token EnrollmentTokenRecord) error {
	return createEnrollmentToken(ctx, database.db, token)
}

func (database *DB) CreateEnrollmentTokenWithAudit(ctx context.Context, token EnrollmentTokenRecord, entry model.AuditEntry) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment token creation: %w", err)
	}
	defer tx.Rollback()
	if err := createEnrollmentToken(ctx, tx, token); err != nil {
		return err
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment token creation: %w", err)
	}
	return nil
}

func createEnrollmentToken(ctx context.Context, executor contextExecer, token EnrollmentTokenRecord) error {
	var existing int
	if err := executor.QueryRowContext(ctx, `SELECT COUNT(*) FROM enrollment_tokens WHERE operation_id = ?`, token.OperationID).Scan(&existing); err != nil {
		return fmt.Errorf("inspect enrollment token operation: %w", err)
	}
	if existing != 0 {
		return ErrOperationConflict
	}
	_, err := executor.ExecContext(ctx, `
		INSERT INTO enrollment_tokens(
			id, token_hash, scope_json, created_by_principal_id, operation_id, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, token.ID, token.Hash, string(token.ScopeJSON), token.CreatedByPrincipalID, token.OperationID, formatTime(token.CreatedAt), formatTime(token.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}
	return nil
}

func (database *DB) GetEnrollmentTokenByOperation(ctx context.Context, operationID string) (EnrollmentTokenRecord, error) {
	var record EnrollmentTokenRecord
	var scopeJSON, createdAt, expiresAt string
	var consumedAt sql.NullString
	err := database.db.QueryRowContext(ctx, `
		SELECT id, token_hash, scope_json, created_by_principal_id, operation_id, created_at, expires_at,
		       consumed_at, COALESCE(consumed_by_node_id, ''), COALESCE(consumed_request_id, ''), consumed_request_digest
		FROM enrollment_tokens WHERE operation_id = ?
	`, operationID).Scan(&record.ID, &record.Hash, &scopeJSON, &record.CreatedByPrincipalID, &record.OperationID,
		&createdAt, &expiresAt, &consumedAt, &record.ConsumedByNodeID, &record.ConsumedRequestID, &record.ConsumedRequestDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentTokenRecord{}, ErrEnrollmentTokenInvalid
	}
	if err != nil {
		return EnrollmentTokenRecord{}, fmt.Errorf("read enrollment token operation: %w", err)
	}
	record.ScopeJSON = json.RawMessage(scopeJSON)
	if record.CreatedAt, err = parseTime(createdAt); err != nil {
		return EnrollmentTokenRecord{}, fmt.Errorf("parse enrollment token creation time: %w", err)
	}
	if record.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return EnrollmentTokenRecord{}, fmt.Errorf("parse enrollment token expiry: %w", err)
	}
	if consumedAt.Valid {
		value, parseErr := parseTime(consumedAt.String)
		if parseErr != nil {
			return EnrollmentTokenRecord{}, fmt.Errorf("parse enrollment token consumption time: %w", parseErr)
		}
		record.ConsumedAt = &value
	}
	return record, nil
}

func (database *DB) GetEnrollmentToken(ctx context.Context, tokenHash []byte, now time.Time) (EnrollmentTokenRecord, error) {
	var record EnrollmentTokenRecord
	var scopeJSON, createdAt, expiresAt string
	var consumedAt sql.NullString
	err := database.db.QueryRowContext(ctx, `
		SELECT id, token_hash, scope_json, created_by_principal_id, operation_id, created_at, expires_at,
		       consumed_at, COALESCE(consumed_by_node_id, ''), COALESCE(consumed_request_id, ''), consumed_request_digest
		FROM enrollment_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&record.ID, &record.Hash, &scopeJSON, &record.CreatedByPrincipalID, &record.OperationID,
		&createdAt, &expiresAt, &consumedAt, &record.ConsumedByNodeID, &record.ConsumedRequestID, &record.ConsumedRequestDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentTokenRecord{}, ErrEnrollmentTokenInvalid
	}
	if err != nil {
		return EnrollmentTokenRecord{}, fmt.Errorf("read enrollment token: %w", err)
	}
	record.ScopeJSON = json.RawMessage(scopeJSON)
	if record.CreatedAt, err = parseTime(createdAt); err != nil {
		return EnrollmentTokenRecord{}, fmt.Errorf("parse enrollment token creation time: %w", err)
	}
	if record.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return EnrollmentTokenRecord{}, fmt.Errorf("parse enrollment token expiry: %w", err)
	}
	if consumedAt.Valid {
		value, err := parseTime(consumedAt.String)
		if err != nil {
			return EnrollmentTokenRecord{}, fmt.Errorf("parse enrollment token consumption time: %w", err)
		}
		record.ConsumedAt = &value
		return record, nil
	}
	if !now.Before(record.ExpiresAt) {
		return EnrollmentTokenRecord{}, ErrEnrollmentTokenExpired
	}
	return record, nil
}

func (database *DB) EnrollNode(ctx context.Context, tokenHash []byte, now time.Time, node model.Node) error {
	return database.enrollNode(ctx, tokenHash, now, node, nil)
}

func (database *DB) EnrollNodeWithAudit(ctx context.Context, tokenHash []byte, now time.Time, node model.Node, entry model.AuditEntry) error {
	return database.enrollNode(ctx, tokenHash, now, node, &entry)
}

func (database *DB) EnrollNodeRequestWithAudit(ctx context.Context, tokenHash []byte, now time.Time, requestID string, requestDigest []byte, node model.Node, entry model.AuditEntry) error {
	return database.enrollNodeRequest(ctx, tokenHash, now, requestID, requestDigest, node, &entry)
}

func (database *DB) enrollNode(ctx context.Context, tokenHash []byte, now time.Time, node model.Node, entry *model.AuditEntry) error {
	return database.enrollNodeRequest(ctx, tokenHash, now, "", nil, node, entry)
}

func (database *DB) enrollNodeRequest(ctx context.Context, tokenHash []byte, now time.Time, requestID string, requestDigest []byte, node model.Node, entry *model.AuditEntry) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment: %w", err)
	}
	defer tx.Rollback()

	var expiresAt string
	var consumedAt sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT expires_at, consumed_at FROM enrollment_tokens WHERE token_hash = ?`, tokenHash).Scan(&expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentTokenInvalid
	}
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
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
	if err := claimNodeIdentity(ctx, tx, node.ID, "legacy:"+node.ID, now); err != nil {
		return err
	}

	tags, err := json.Marshal(node.Tags)
	if err != nil {
		return fmt.Errorf("encode node tags: %w", err)
	}
	capabilities := node.Capabilities
	if len(capabilities) == 0 {
		capabilities = json.RawMessage(`{}`)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO nodes(
			id, name, node_type, platform, platform_version, status, tags_json, capabilities_json, capabilities_verification, public_key,
			certificate_pem, enrolled_at, last_policy_revision
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, node.ID, node.Name, node.Type, node.Platform, node.PlatformVersion, node.Status, string(tags), string(capabilities), node.CapabilitiesVerification, node.PublicKey,
		node.CertificatePEM, formatTime(node.EnrolledAt), node.LastPolicyRevision)
	if err != nil {
		return fmt.Errorf("insert enrolled node: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE enrollment_tokens
		SET consumed_at = ?, consumed_by_node_id = ?, consumed_request_id = ?, consumed_request_digest = ?
		WHERE token_hash = ? AND consumed_at IS NULL
	`, formatTime(now), node.ID, requestID, requestDigest, tokenHash)
	if err != nil {
		return fmt.Errorf("consume enrollment token: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrEnrollmentTokenUsed
	}
	if entry != nil {
		if err := insertAuditEntry(ctx, tx, *entry); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment: %w", err)
	}
	return nil
}

func (database *DB) ResolveEnrollmentReplay(ctx context.Context, tokenHash []byte, requestID string, requestDigest []byte) (model.Node, error) {
	record, err := database.GetEnrollmentToken(ctx, tokenHash, time.Time{})
	if err != nil {
		return model.Node{}, err
	}
	if record.ConsumedAt == nil || record.ConsumedByNodeID == "" {
		return model.Node{}, ErrEnrollmentTokenInvalid
	}
	if record.ConsumedRequestID != requestID || !bytes.Equal(record.ConsumedRequestDigest, requestDigest) {
		return model.Node{}, ErrEnrollmentTokenUsed
	}
	return database.GetNode(ctx, record.ConsumedByNodeID)
}

func (database *DB) GetNode(ctx context.Context, id string) (model.Node, error) {
	row := database.db.QueryRowContext(ctx, `
		SELECT id, name, node_type, platform, platform_version, status, tags_json, capabilities_json, capabilities_verification, public_key,
		       certificate_pem, enrolled_at, last_seen_at, revoked_at, last_policy_revision
		FROM nodes WHERE id = ?
	`, id)
	return scanNode(row)
}

func (database *DB) ListNodes(ctx context.Context) ([]model.Node, error) {
	rows, err := database.db.QueryContext(ctx, `
		SELECT id, name, node_type, platform, platform_version, status, tags_json, capabilities_json, capabilities_verification, public_key,
		       certificate_pem, enrolled_at, last_seen_at, revoked_at, last_policy_revision
		FROM nodes ORDER BY name, id
	`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	var result []model.Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	return result, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanNode(row rowScanner) (model.Node, error) {
	var node model.Node
	var tagsJSON, capabilitiesJSON, enrolledAt string
	var lastSeenAt, revokedAt sql.NullString
	if err := row.Scan(
		&node.ID, &node.Name, &node.Type, &node.Platform, &node.PlatformVersion, &node.Status, &tagsJSON, &capabilitiesJSON, &node.CapabilitiesVerification,
		&node.PublicKey, &node.CertificatePEM, &enrolledAt, &lastSeenAt, &revokedAt,
		&node.LastPolicyRevision,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Node{}, ErrNodeNotFound
		}
		return model.Node{}, fmt.Errorf("scan node: %w", err)
	}
	if err := json.Unmarshal([]byte(tagsJSON), &node.Tags); err != nil {
		return model.Node{}, fmt.Errorf("decode node tags: %w", err)
	}
	node.Capabilities = json.RawMessage(capabilitiesJSON)
	var err error
	if node.EnrolledAt, err = parseTime(enrolledAt); err != nil {
		return model.Node{}, fmt.Errorf("parse enrolled time: %w", err)
	}
	if lastSeenAt.Valid {
		value, err := parseTime(lastSeenAt.String)
		if err != nil {
			return model.Node{}, fmt.Errorf("parse last-seen time: %w", err)
		}
		node.LastSeenAt = &value
	}
	if revokedAt.Valid {
		value, err := parseTime(revokedAt.String)
		if err != nil {
			return model.Node{}, fmt.Errorf("parse revoked time: %w", err)
		}
		node.RevokedAt = &value
	}
	return node, nil
}

func (database *DB) SetNodeStatus(ctx context.Context, id string, status model.NodeStatus, now time.Time) error {
	return database.setNodeStatus(ctx, id, status, now, nil)
}

func (database *DB) SetNodeStatusWithAudit(ctx context.Context, id string, status model.NodeStatus, now time.Time, entry model.AuditEntry) error {
	return database.setNodeStatus(ctx, id, status, now, &entry)
}

func (database *DB) setNodeStatus(ctx context.Context, id string, status model.NodeStatus, now time.Time, entry *model.AuditEntry) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node status update: %w", err)
	}
	defer tx.Rollback()
	var currentStatus model.NodeStatus
	if err := tx.QueryRowContext(ctx, `SELECT status FROM nodes WHERE id = ?`, id).Scan(&currentStatus); errors.Is(err, sql.ErrNoRows) {
		return ErrNodeNotFound
	} else if err != nil {
		return fmt.Errorf("read current node status: %w", err)
	}
	if currentStatus == model.NodeRevoked && status != model.NodeRevoked {
		return ErrNodeRevoked
	}
	var revoked any
	if status == model.NodeRevoked {
		revoked = formatTime(now)
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodes SET status = ?, revoked_at = ? WHERE id = ?`, status, revoked, id)
	if err != nil {
		return fmt.Errorf("set node status: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read node update count: %w", err)
	}
	if count == 0 {
		return ErrNodeNotFound
	}
	if entry != nil {
		if err := insertAuditEntry(ctx, tx, *entry); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node status update: %w", err)
	}
	return nil
}

func (database *DB) UpdateNodeMetadataWithAudit(ctx context.Context, id, name string, tags []string, entry model.AuditEntry) error {
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node metadata update: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id = ?`, id).Scan(&exists); err != nil {
		return fmt.Errorf("read node for metadata update: %w", err)
	}
	if exists != 1 {
		return ErrNodeNotFound
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("encode node tags: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET name = ?, tags_json = ? WHERE id = ?`, name, string(tagsJSON), id); err != nil {
		return fmt.Errorf("update node metadata: %w", err)
	}
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node metadata update: %w", err)
	}
	return nil
}
