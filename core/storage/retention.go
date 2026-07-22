package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
)

var (
	ErrRetentionProjectionNotReady = errors.New("required projection has not durably processed events")
	ErrRetentionIntegrity          = errors.New("event retention tombstone chain failed verification")
)

type RetentionResult struct {
	Deleted            int64
	SafeThroughOrdinal uint64
	SafeThroughAt      time.Time
	SafeThroughID      string
	TombstoneHash      string
}

// EventRetentionCutoffs defines the oldest record each class may retain. Class
// and sensitivity cutoffs may only move forward from DefaultBefore, making
// overrides privacy-preserving reductions rather than covert extensions.
type EventRetentionCutoffs struct {
	DefaultBefore    time.Time
	ByClassification map[model.EvidenceClass]time.Time
	BySensitivity    map[model.Sensitivity]time.Time
}

type retentionRuleRecord struct {
	Value  string `json:"value"`
	Before string `json:"before"`
}

type retentionPolicyRecord struct {
	DefaultBefore    string                `json:"defaultBefore"`
	ByClassification []retentionRuleRecord `json:"byClassification,omitempty"`
	BySensitivity    []retentionRuleRecord `json:"bySensitivity,omitempty"`
}

type retentionCandidate struct {
	ordinal uint64
	id      string
	wire    []byte
}

// PruneEvents deletes a bounded batch only after every required durable
// projection has advanced through the candidate. It never compacts audit data.
func (database *DB) PruneEvents(ctx context.Context, cutoff time.Time, requiredProjections []string, batchSize int) (RetentionResult, error) {
	return database.PruneEventsWithCutoffs(ctx, EventRetentionCutoffs{DefaultBefore: cutoff}, requiredProjections, batchSize)
}

// PruneEventsWithCutoffs applies privacy-reducing class and sensitivity
// overrides while preserving the projection gate and a chained deletion
// receipt. Tombstone metadata is committed atomically with source deletion.
func (database *DB) PruneEventsWithCutoffs(
	ctx context.Context,
	cutoffs EventRetentionCutoffs,
	requiredProjections []string,
	batchSize int,
) (RetentionResult, error) {
	policyJSON, err := canonicalRetentionPolicy(cutoffs)
	if err != nil {
		return RetentionResult{}, err
	}
	if len(requiredProjections) == 0 {
		return RetentionResult{}, errors.New("at least one required projection is required for safe pruning")
	}
	seenProjection := make(map[string]struct{}, len(requiredProjections))
	for _, projection := range requiredProjections {
		if strings.TrimSpace(projection) == "" {
			return RetentionResult{}, errors.New("required projection names cannot be empty")
		}
		if _, exists := seenProjection[projection]; exists {
			return RetentionResult{}, fmt.Errorf("required projection %q is duplicated", projection)
		}
		seenProjection[projection] = struct{}{}
	}
	if batchSize <= 0 || batchSize > 10_000 {
		batchSize = 500
	}

	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return RetentionResult{}, fmt.Errorf("begin event retention: %w", err)
	}
	defer tx.Rollback()
	if err := verifyRetentionTombstonesTx(ctx, tx); err != nil {
		return RetentionResult{}, err
	}

	safeOrdinal, safeAt, safeID, err := retentionSafeCursor(ctx, tx, requiredProjections)
	if err != nil {
		return RetentionResult{}, err
	}
	candidates, err := selectRetentionCandidates(ctx, tx, cutoffs, safeOrdinal, batchSize)
	if err != nil {
		return RetentionResult{}, err
	}
	if len(candidates) == 0 {
		if err := tx.Commit(); err != nil {
			return RetentionResult{}, fmt.Errorf("commit empty event retention: %w", err)
		}
		return RetentionResult{SafeThroughOrdinal: safeOrdinal, SafeThroughAt: safeAt, SafeThroughID: safeID}, nil
	}

	batchHash := retentionBatchHash(candidates)
	var previousCount uint64
	var previousHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT tombstone_count, head_hash FROM event_retention_state WHERE id = 1
	`).Scan(&previousCount, &previousHash); err != nil {
		return RetentionResult{}, fmt.Errorf("read event retention state: %w", err)
	}
	prunedAt := time.Now().UTC()
	cutoffAtText := formatTime(cutoffs.DefaultBefore)
	prunedAtText := formatTime(prunedAt)
	tombstoneHash := retentionTombstoneHash(
		previousHash, candidates[0].ordinal, candidates[len(candidates)-1].ordinal,
		uint64(len(candidates)), batchHash, string(policyJSON), cutoffAtText, prunedAtText,
	)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO event_retention_tombstones(
			first_ingest_ordinal, last_ingest_ordinal, event_count, batch_hash, policy_json,
			cutoff_at, pruned_at, previous_hash, tombstone_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, candidates[0].ordinal, candidates[len(candidates)-1].ordinal, len(candidates), batchHash,
		string(policyJSON), cutoffAtText, prunedAtText, previousHash, tombstoneHash); err != nil {
		return RetentionResult{}, fmt.Errorf("record event retention tombstone: %w", err)
	}
	stateResult, err := tx.ExecContext(ctx, `
		UPDATE event_retention_state SET tombstone_count = ?, head_hash = ?
		WHERE id = 1 AND tombstone_count = ? AND head_hash = ?
	`, previousCount+1, tombstoneHash, previousCount, previousHash)
	if err != nil {
		return RetentionResult{}, fmt.Errorf("advance event retention state: %w", err)
	}
	updated, err := stateResult.RowsAffected()
	if err != nil || updated != 1 {
		return RetentionResult{}, errors.New("event retention state changed concurrently")
	}

	placeholders := make([]string, 0, len(candidates))
	arguments := make([]any, 0, len(candidates))
	for _, item := range candidates {
		placeholders = append(placeholders, "?")
		arguments = append(arguments, item.ordinal)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM events WHERE ingest_ordinal IN (`+strings.Join(placeholders, ",")+`)`, arguments...)
	if err != nil {
		return RetentionResult{}, fmt.Errorf("prune retained events: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != int64(len(candidates)) {
		return RetentionResult{}, fmt.Errorf("retention deletion count %d does not match tombstone count %d", deleted, len(candidates))
	}
	if err := tx.Commit(); err != nil {
		return RetentionResult{}, fmt.Errorf("commit event retention: %w", err)
	}
	outcome := RetentionResult{
		Deleted: deleted, SafeThroughOrdinal: safeOrdinal, SafeThroughAt: safeAt,
		SafeThroughID: safeID, TombstoneHash: tombstoneHash,
	}
	// secure_delete clears deleted cells; truncating the WAL prevents retained
	// frames from outliving the committed privacy deletion. The receipt remains
	// committed and is returned even if the durability cleanup fails.
	if _, err := database.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return outcome, fmt.Errorf("events were pruned but the SQLite WAL could not be truncated: %w", err)
	}
	return outcome, nil
}

func retentionSafeCursor(ctx context.Context, tx *sql.Tx, requiredProjections []string) (uint64, time.Time, string, error) {
	var safeOrdinal uint64
	var safeAt time.Time
	var safeID string
	for _, projection := range requiredProjections {
		var ordinal uint64
		var receivedAt int64
		var eventID string
		err := tx.QueryRowContext(ctx, `
			SELECT last_ingest_ordinal, last_received_at, last_event_id FROM projection_cursors WHERE projection = ?
		`, projection).Scan(&ordinal, &receivedAt, &eventID)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, "", fmt.Errorf("%w: %s", ErrRetentionProjectionNotReady, projection)
		}
		if err != nil {
			return 0, time.Time{}, "", fmt.Errorf("read retention projection %s: %w", projection, err)
		}
		if ordinal == 0 || receivedAt == sortableTime(time.Time{}) || eventID == "" {
			return 0, time.Time{}, "", fmt.Errorf("%w: %s", ErrRetentionProjectionNotReady, projection)
		}
		cursorTime := parseSortableTime(receivedAt)
		if safeOrdinal == 0 || ordinal < safeOrdinal {
			safeOrdinal, safeAt, safeID = ordinal, cursorTime, eventID
		}
	}
	return safeOrdinal, safeAt, safeID, nil
}

func selectRetentionCandidates(ctx context.Context, tx *sql.Tx, cutoffs EventRetentionCutoffs, safeOrdinal uint64, batchSize int) ([]retentionCandidate, error) {
	clauses := []string{"received_at < ?"}
	arguments := []any{sortableTime(cutoffs.DefaultBefore)}
	classes := make([]string, 0, len(cutoffs.ByClassification))
	for class := range cutoffs.ByClassification {
		classes = append(classes, string(class))
	}
	sort.Strings(classes)
	for _, class := range classes {
		clauses = append(clauses, "(classification = ? AND received_at < ?)")
		arguments = append(arguments, class, sortableTime(cutoffs.ByClassification[model.EvidenceClass(class)]))
	}
	sensitivities := make([]string, 0, len(cutoffs.BySensitivity))
	for sensitivity := range cutoffs.BySensitivity {
		sensitivities = append(sensitivities, string(sensitivity))
	}
	sort.Strings(sensitivities)
	for _, sensitivity := range sensitivities {
		clauses = append(clauses, "(sensitivity = ? AND received_at < ?)")
		arguments = append(arguments, sensitivity, sortableTime(cutoffs.BySensitivity[model.Sensitivity(sensitivity)]))
	}
	arguments = append(arguments, safeOrdinal, batchSize)
	rows, err := tx.QueryContext(ctx, `
		SELECT ingest_ordinal, id, envelope_proto FROM events
		WHERE (`+strings.Join(clauses, " OR ")+`) AND ingest_ordinal <= ?
		ORDER BY ingest_ordinal ASC LIMIT ?
	`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("select retained events: %w", err)
	}
	defer rows.Close()
	var candidates []retentionCandidate
	for rows.Next() {
		var item retentionCandidate
		if err := rows.Scan(&item.ordinal, &item.id, &item.wire); err != nil {
			return nil, fmt.Errorf("scan retained event: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retained events: %w", err)
	}
	return candidates, nil
}

func canonicalRetentionPolicy(cutoffs EventRetentionCutoffs) ([]byte, error) {
	if cutoffs.DefaultBefore.IsZero() {
		return nil, errors.New("retention cutoff is required")
	}
	record := retentionPolicyRecord{DefaultBefore: formatTime(cutoffs.DefaultBefore)}
	for class, before := range cutoffs.ByClassification {
		if !class.Valid() {
			return nil, fmt.Errorf("invalid retention evidence classification %q", class)
		}
		if before.IsZero() || before.Before(cutoffs.DefaultBefore) {
			return nil, fmt.Errorf("retention classification cutoff %q cannot extend the default", class)
		}
		record.ByClassification = append(record.ByClassification, retentionRuleRecord{Value: string(class), Before: formatTime(before)})
	}
	for sensitivity, before := range cutoffs.BySensitivity {
		if !sensitivity.Valid() {
			return nil, fmt.Errorf("invalid retention sensitivity %q", sensitivity)
		}
		if before.IsZero() || before.Before(cutoffs.DefaultBefore) {
			return nil, fmt.Errorf("retention sensitivity cutoff %q cannot extend the default", sensitivity)
		}
		record.BySensitivity = append(record.BySensitivity, retentionRuleRecord{Value: string(sensitivity), Before: formatTime(before)})
	}
	sort.Slice(record.ByClassification, func(i, j int) bool { return record.ByClassification[i].Value < record.ByClassification[j].Value })
	sort.Slice(record.BySensitivity, func(i, j int) bool { return record.BySensitivity[i].Value < record.BySensitivity[j].Value })
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode retention policy: %w", err)
	}
	return encoded, nil
}

func retentionBatchHash(candidates []retentionCandidate) string {
	hasher := sha256.New()
	writeRetentionField(hasher, []byte("AntiFlock-Event-Retention-Batch-v1"))
	for _, item := range candidates {
		writeRetentionUint64(hasher, item.ordinal)
		writeRetentionField(hasher, []byte(item.id))
		wireDigest := sha256.Sum256(item.wire)
		writeRetentionField(hasher, wireDigest[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func retentionTombstoneHash(previousHash string, first, last, count uint64, batchHash, policyJSON, cutoffAt, prunedAt string) string {
	hasher := sha256.New()
	writeRetentionField(hasher, []byte("AntiFlock-Event-Retention-Tombstone-v1"))
	writeRetentionField(hasher, []byte(previousHash))
	writeRetentionUint64(hasher, first)
	writeRetentionUint64(hasher, last)
	writeRetentionUint64(hasher, count)
	writeRetentionField(hasher, []byte(batchHash))
	writeRetentionField(hasher, []byte(policyJSON))
	writeRetentionField(hasher, []byte(cutoffAt))
	writeRetentionField(hasher, []byte(prunedAt))
	return hex.EncodeToString(hasher.Sum(nil))
}

func writeRetentionField(hasher hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

func writeRetentionUint64(hasher hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = hasher.Write(encoded[:])
}

// VerifyEventRetentionTombstones checks the complete local deletion-receipt
// chain and its transactionally maintained head. A separately protected
// witness is still required to detect coordinated rollback of the whole DB.
func (database *DB) VerifyEventRetentionTombstones(ctx context.Context) error {
	tx, err := database.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin event retention verification: %w", err)
	}
	defer tx.Rollback()
	if err := verifyRetentionTombstonesTx(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit event retention verification: %w", err)
	}
	return nil
}

func verifyRetentionTombstonesTx(ctx context.Context, tx *sql.Tx) error {
	var expectedCount uint64
	var expectedHead string
	if err := tx.QueryRowContext(ctx, `
		SELECT tombstone_count, head_hash FROM event_retention_state WHERE id = 1
	`).Scan(&expectedCount, &expectedHead); err != nil {
		return fmt.Errorf("%w: read state: %v", ErrRetentionIntegrity, err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, first_ingest_ordinal, last_ingest_ordinal, event_count, batch_hash,
		       policy_json, cutoff_at, pruned_at, previous_hash, tombstone_hash
		FROM event_retention_tombstones ORDER BY id ASC
	`)
	if err != nil {
		return fmt.Errorf("%w: read tombstones: %v", ErrRetentionIntegrity, err)
	}
	defer rows.Close()
	var count uint64
	var previousID uint64
	var previousHash string
	for rows.Next() {
		var id, first, last, eventCount uint64
		var batchHash, policyJSON, cutoffAt, prunedAt, storedPrevious, storedHash string
		if err := rows.Scan(&id, &first, &last, &eventCount, &batchHash, &policyJSON, &cutoffAt, &prunedAt, &storedPrevious, &storedHash); err != nil {
			return fmt.Errorf("%w: scan tombstone: %v", ErrRetentionIntegrity, err)
		}
		if id <= previousID || first == 0 || last < first || eventCount == 0 || eventCount > last-first+1 {
			return fmt.Errorf("%w: invalid tombstone bounds at row %d", ErrRetentionIntegrity, id)
		}
		if !validSHA256Hex(batchHash) || !validSHA256Hex(storedHash) || (storedPrevious != "" && !validSHA256Hex(storedPrevious)) {
			return fmt.Errorf("%w: invalid tombstone digest at row %d", ErrRetentionIntegrity, id)
		}
		if storedPrevious != previousHash {
			return fmt.Errorf("%w: previous hash mismatch at row %d", ErrRetentionIntegrity, id)
		}
		var policy retentionPolicyRecord
		if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
			return fmt.Errorf("%w: invalid policy at row %d", ErrRetentionIntegrity, id)
		}
		canonicalPolicy, err := json.Marshal(policy)
		if err != nil || string(canonicalPolicy) != policyJSON {
			return fmt.Errorf("%w: noncanonical policy at row %d", ErrRetentionIntegrity, id)
		}
		if _, err := parseTime(cutoffAt); err != nil {
			return fmt.Errorf("%w: invalid cutoff at row %d", ErrRetentionIntegrity, id)
		}
		if _, err := parseTime(prunedAt); err != nil {
			return fmt.Errorf("%w: invalid prune time at row %d", ErrRetentionIntegrity, id)
		}
		computed := retentionTombstoneHash(storedPrevious, first, last, eventCount, batchHash, policyJSON, cutoffAt, prunedAt)
		if computed != storedHash {
			return fmt.Errorf("%w: hash mismatch at row %d", ErrRetentionIntegrity, id)
		}
		count++
		previousID, previousHash = id, storedHash
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate tombstones: %v", ErrRetentionIntegrity, err)
	}
	if count != expectedCount || previousHash != expectedHead {
		return fmt.Errorf("%w: state head does not match the tombstone journal", ErrRetentionIntegrity)
	}
	return nil
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
