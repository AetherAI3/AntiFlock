package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
)

var (
	ErrEventSequenceConflict = errors.New("event sequence conflicts with a different stored event")
	ErrEventSequenceGap      = errors.New("event sequence is not contiguous")
	ErrEventBootRegression   = errors.New("event boot id was already closed")
	ErrEventNotFound         = errors.New("event not found")
)

type NodeEventState struct {
	NodeID                    string
	CurrentBootID             string
	HighestContiguousSequence uint64
	LastEventID               string
	UpdatedAt                 time.Time
}

func (database *DB) GetNodeEventState(ctx context.Context, nodeID string) (NodeEventState, error) {
	var state NodeEventState
	var updatedAt string
	err := database.db.QueryRowContext(ctx, `
		SELECT node_id, current_boot_id, highest_contiguous_sequence, last_event_id, updated_at
		FROM node_event_state WHERE node_id = ?
	`, nodeID).Scan(&state.NodeID, &state.CurrentBootID, &state.HighestContiguousSequence, &state.LastEventID, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeEventState{NodeID: nodeID}, nil
	}
	if err != nil {
		return NodeEventState{}, fmt.Errorf("read node event state: %w", err)
	}
	if state.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return NodeEventState{}, fmt.Errorf("parse node event state update time: %w", err)
	}
	return state, nil
}

func (database *DB) AppendEvent(ctx context.Context, event model.EventEnvelope) (bool, error) {
	if err := event.Validate(); err != nil {
		return false, err
	}
	if event.ReceivedAt.IsZero() {
		return false, errors.New("event received time is required for durable ingestion")
	}
	if err := model.ValidateEvidenceAt(event, event.ReceivedAt); err != nil {
		return false, err
	}
	encoded, err := marshalEvent(event)
	if err != nil {
		return false, err
	}
	if len(encoded) > model.MaximumEventWireBytes {
		return false, fmt.Errorf("event envelope exceeds %d bytes", model.MaximumEventWireBytes)
	}
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin event append: %w", err)
	}
	defer tx.Rollback()

	var existingBytes []byte
	err = tx.QueryRowContext(ctx, `SELECT envelope_proto FROM events WHERE id = ?`, event.ID).Scan(&existingBytes)
	if err == nil {
		existing, decodeErr := unmarshalEvent(existingBytes)
		if decodeErr != nil {
			return false, decodeErr
		}
		incomingSource, marshalErr := marshalSourceEvent(event)
		if marshalErr != nil {
			return false, marshalErr
		}
		existingSource, marshalErr := marshalSourceEvent(existing)
		if marshalErr != nil {
			return false, marshalErr
		}
		if bytes.Equal(incomingSource, existingSource) {
			return false, nil
		}
		return false, ErrEventSequenceConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("inspect event id: %w", err)
	}

	if err := advanceEventSequence(ctx, tx, event); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO events(
			id, schema_version, deployment_id, node_id, kind, observed_at, received_at, sequence, boot_id,
			classification, confidence, sensitivity, envelope_proto
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.SchemaVersion, event.DeploymentID, event.NodeID, event.Kind, sortableTime(event.ObservedAt),
		sortableTime(event.ReceivedAt), event.Sequence, event.BootID, event.Classification, event.Confidence,
		event.Sensitivity, encoded); err != nil {
		return false, fmt.Errorf("append event: %w", err)
	}
	if err := advanceNodeLastSeen(ctx, tx, event.NodeID, event.ReceivedAt); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit event append: %w", err)
	}
	return true, nil
}

func advanceNodeLastSeen(ctx context.Context, tx *sql.Tx, nodeID string, receivedAt time.Time) error {
	var stored sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT last_seen_at FROM nodes WHERE id = ?`, nodeID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		// Storage contract tests may append synthetic envelopes directly. The
		// authenticated event Store always establishes an enrolled node first.
		return nil
	}
	if err != nil {
		return fmt.Errorf("read node last-seen time: %w", err)
	}
	if stored.Valid {
		previous, parseErr := parseTime(stored.String)
		if parseErr != nil {
			return fmt.Errorf("parse node last-seen time: %w", parseErr)
		}
		if !receivedAt.After(previous) {
			return nil
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET last_seen_at = ? WHERE id = ?`, formatTime(receivedAt), nodeID); err != nil {
		return fmt.Errorf("advance node last-seen time: %w", err)
	}
	return nil
}

func advanceEventSequence(ctx context.Context, tx *sql.Tx, event model.EventEnvelope) error {
	var currentBoot string
	var highest uint64
	err := tx.QueryRowContext(ctx, `
		SELECT current_boot_id, highest_contiguous_sequence FROM node_event_state WHERE node_id = ?
	`, event.NodeID).Scan(&currentBoot, &highest)
	if errors.Is(err, sql.ErrNoRows) {
		if event.Sequence != 1 {
			return fmt.Errorf("%w: first event for node %s must be sequence 1", ErrEventSequenceGap, event.NodeID)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_event_state(node_id, current_boot_id, highest_contiguous_sequence, last_event_id, updated_at)
			VALUES (?, ?, ?, ?, ?)
		`, event.NodeID, event.BootID, event.Sequence, event.ID, formatTime(event.ReceivedAt)); err != nil {
			return fmt.Errorf("initialize node event state: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_event_boots(node_id, boot_id, highest_contiguous_sequence, started_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
		`, event.NodeID, event.BootID, event.Sequence, formatTime(event.ObservedAt), formatTime(event.ReceivedAt)); err != nil {
			return fmt.Errorf("record node event boot: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read node event state: %w", err)
	}
	if currentBoot != event.BootID {
		var seen int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_event_boots WHERE node_id = ? AND boot_id = ?`, event.NodeID, event.BootID).Scan(&seen); err != nil {
			return fmt.Errorf("inspect node boot history: %w", err)
		}
		if seen != 0 {
			return fmt.Errorf("%w: %s", ErrEventBootRegression, event.BootID)
		}
		if event.Sequence != 1 {
			return fmt.Errorf("%w: a new boot must begin at sequence 1", ErrEventSequenceGap)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_event_boots(node_id, boot_id, highest_contiguous_sequence, started_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
		`, event.NodeID, event.BootID, event.Sequence, formatTime(event.ObservedAt), formatTime(event.ReceivedAt)); err != nil {
			return fmt.Errorf("record new node boot: %w", err)
		}
	} else if event.Sequence != highest+1 {
		if event.Sequence <= highest {
			return ErrEventSequenceConflict
		}
		return fmt.Errorf("%w: got %d after %d", ErrEventSequenceGap, event.Sequence, highest)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_event_state SET current_boot_id = ?, highest_contiguous_sequence = ?, last_event_id = ?, updated_at = ?
		WHERE node_id = ?
	`, event.BootID, event.Sequence, event.ID, formatTime(event.ReceivedAt), event.NodeID); err != nil {
		return fmt.Errorf("advance node event state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_event_boots SET highest_contiguous_sequence = ?, updated_at = ?
		WHERE node_id = ? AND boot_id = ?
	`, event.Sequence, formatTime(event.ReceivedAt), event.NodeID, event.BootID); err != nil {
		return fmt.Errorf("advance node boot sequence: %w", err)
	}
	return nil
}

func (database *DB) ListEvents(ctx context.Context, after time.Time, limit int) ([]model.EventEnvelope, error) {
	return database.ListEventsPage(ctx, after, "", limit)
}

func (database *DB) GetEvent(ctx context.Context, eventID string) (model.EventEnvelope, error) {
	var ordinal uint64
	var encoded []byte
	err := database.db.QueryRowContext(ctx, `SELECT ingest_ordinal, envelope_proto FROM events WHERE id = ?`, eventID).Scan(&ordinal, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return model.EventEnvelope{}, ErrEventNotFound
	}
	if err != nil {
		return model.EventEnvelope{}, fmt.Errorf("get event: %w", err)
	}
	event, err := unmarshalEvent(encoded)
	if err == nil {
		event.IngestOrdinal = ordinal
	}
	return event, err
}

func (database *DB) ListEventsPage(ctx context.Context, after time.Time, afterEventID string, limit int) ([]model.EventEnvelope, error) {
	var afterOrdinal uint64
	if afterEventID != "" {
		err := database.db.QueryRowContext(ctx, `SELECT ingest_ordinal FROM events WHERE id = ?`, afterEventID).Scan(&afterOrdinal)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEventNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("resolve event cursor: %w", err)
		}
	} else if !after.IsZero() {
		if err := database.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(ingest_ordinal), 0) FROM events WHERE received_at <= ?`, sortableTime(after)).Scan(&afterOrdinal); err != nil {
			return nil, fmt.Errorf("resolve time cursor: %w", err)
		}
	}
	return database.ListEventsFromOrdinal(ctx, afterOrdinal, limit)
}

func (database *DB) ListEventsFromOrdinal(ctx context.Context, afterOrdinal uint64, limit int) ([]model.EventEnvelope, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := database.db.QueryContext(ctx, `
		SELECT ingest_ordinal, envelope_proto FROM events
		WHERE ingest_ordinal > ?
		ORDER BY ingest_ordinal ASC
		LIMIT ?
	`, afterOrdinal, limit)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()
	var result []model.EventEnvelope
	for rows.Next() {
		var ordinal uint64
		var encoded []byte
		if err := rows.Scan(&ordinal, &encoded); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		event, err := unmarshalEvent(encoded)
		if err != nil {
			return nil, err
		}
		event.IngestOrdinal = ordinal
		result = append(result, event)
	}
	return result, rows.Err()
}

// ListLatestEventsForNode returns at most one durable event per requested kind,
// choosing the greatest observed time and then the greatest ingest ordinal.
// It is intentionally a storage read, not a cache, so topology and path views
// cannot outlive retention or report facts that were never committed.
func (database *DB) ListLatestEventsForNode(ctx context.Context, nodeID string, kinds []string) ([]model.EventEnvelope, error) {
	if nodeID == "" || strings.TrimSpace(nodeID) != nodeID || len(nodeID) > 128 {
		return nil, errors.New("node id is invalid")
	}
	if len(kinds) == 0 || len(kinds) > 32 {
		return nil, errors.New("between one and 32 event kinds are required")
	}
	arguments := make([]any, 0, len(kinds)+1)
	arguments = append(arguments, nodeID)
	placeholders := make([]string, 0, len(kinds))
	seen := make(map[string]struct{}, len(kinds))
	for _, kind := range kinds {
		if kind == "" || len(kind) > 128 || strings.TrimSpace(kind) != kind || !strings.Contains(kind, ".") {
			return nil, errors.New("event kind is invalid")
		}
		if _, duplicate := seen[kind]; duplicate {
			return nil, errors.New("event kinds must be unique")
		}
		seen[kind] = struct{}{}
		placeholders = append(placeholders, "?")
		arguments = append(arguments, kind)
	}
	rows, err := database.db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT ingest_ordinal, envelope_proto, kind,
			       ROW_NUMBER() OVER (
			           PARTITION BY kind
			           ORDER BY observed_at DESC, ingest_ordinal DESC
			       ) AS event_rank
			FROM events
			WHERE node_id = ? AND kind IN (`+strings.Join(placeholders, ",")+`)
		)
		SELECT ingest_ordinal, envelope_proto
		FROM ranked
		WHERE event_rank = 1
		ORDER BY kind ASC
	`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list latest node events: %w", err)
	}
	defer rows.Close()
	result := make([]model.EventEnvelope, 0, len(kinds))
	for rows.Next() {
		var ordinal uint64
		var encoded []byte
		if err := rows.Scan(&ordinal, &encoded); err != nil {
			return nil, fmt.Errorf("scan latest node event: %w", err)
		}
		event, err := unmarshalEvent(encoded)
		if err != nil {
			return nil, err
		}
		event.IngestOrdinal = ordinal
		result = append(result, event)
	}
	return result, rows.Err()
}

type ProjectionCursor struct {
	Projection        string
	LastIngestOrdinal uint64
	LastReceivedAt    time.Time
	LastEventID       string
	UpdatedAt         time.Time
}

func (database *DB) GetProjectionCursor(ctx context.Context, projection string) (ProjectionCursor, error) {
	var cursor ProjectionCursor
	var receivedAt int64
	var updatedAt string
	err := database.db.QueryRowContext(ctx, `
		SELECT projection, last_ingest_ordinal, last_received_at, last_event_id, updated_at
		FROM projection_cursors WHERE projection = ?
	`, projection).Scan(&cursor.Projection, &cursor.LastIngestOrdinal, &receivedAt, &cursor.LastEventID, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectionCursor{Projection: projection}, nil
	}
	if err != nil {
		return ProjectionCursor{}, fmt.Errorf("read projection cursor: %w", err)
	}
	cursor.LastReceivedAt = parseSortableTime(receivedAt)
	if cursor.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return ProjectionCursor{}, err
	}
	return cursor, nil
}

func (database *DB) SetProjectionCursor(ctx context.Context, cursor ProjectionCursor) error {
	if cursor.Projection == "" || cursor.LastEventID == "" || cursor.UpdatedAt.IsZero() {
		return errors.New("projection, last event id, and update time are required")
	}
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin projection cursor update: %w", err)
	}
	defer tx.Rollback()
	var actualOrdinal uint64
	var actualReceivedAt int64
	if err := tx.QueryRowContext(ctx, `SELECT ingest_ordinal, received_at FROM events WHERE id = ?`, cursor.LastEventID).Scan(&actualOrdinal, &actualReceivedAt); err != nil {
		return fmt.Errorf("resolve projection event cursor: %w", err)
	}
	if cursor.LastIngestOrdinal != 0 && cursor.LastIngestOrdinal != actualOrdinal {
		return errors.New("projection cursor ordinal does not match its event")
	}
	if !cursor.LastReceivedAt.IsZero() && sortableTime(cursor.LastReceivedAt) != actualReceivedAt {
		return errors.New("projection cursor time does not match its event")
	}
	cursor.LastIngestOrdinal = actualOrdinal
	cursor.LastReceivedAt = parseSortableTime(actualReceivedAt)
	var previous uint64
	var previousEventID, previousUpdatedAt string
	err = tx.QueryRowContext(ctx, `
		SELECT last_ingest_ordinal, last_event_id, updated_at FROM projection_cursors WHERE projection = ?
	`, cursor.Projection).Scan(&previous, &previousEventID, &previousUpdatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read existing projection cursor: %w", err)
	}
	if previous > cursor.LastIngestOrdinal {
		return errors.New("projection cursor cannot move backward")
	}
	if err == nil {
		if previous == cursor.LastIngestOrdinal && previousEventID != cursor.LastEventID {
			return errors.New("projection cursor cannot replace an event at the same ordinal")
		}
		previousUpdate, parseErr := parseTime(previousUpdatedAt)
		if parseErr != nil {
			return fmt.Errorf("parse existing projection cursor update time: %w", parseErr)
		}
		if cursor.UpdatedAt.Before(previousUpdate) {
			return errors.New("projection cursor update time cannot move backward")
		}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO projection_cursors(projection, last_ingest_ordinal, last_received_at, last_event_id, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(projection) DO UPDATE SET
			last_ingest_ordinal = excluded.last_ingest_ordinal,
			last_received_at = excluded.last_received_at,
			last_event_id = excluded.last_event_id,
			updated_at = excluded.updated_at
	`, cursor.Projection, cursor.LastIngestOrdinal, sortableTime(cursor.LastReceivedAt), cursor.LastEventID, formatTime(cursor.UpdatedAt))
	if err != nil {
		return fmt.Errorf("write projection cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit projection cursor: %w", err)
	}
	return nil
}

func marshalEvent(event model.EventEnvelope) ([]byte, error) {
	wire, err := model.EventToProto(event)
	if err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode event protobuf: %w", err)
	}
	return encoded, nil
}

func marshalSourceEvent(event model.EventEnvelope) ([]byte, error) {
	wire, err := model.EventToProto(event)
	if err != nil {
		return nil, err
	}
	wire.ReceivedAt = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode source event protobuf: %w", err)
	}
	return encoded, nil
}

func unmarshalEvent(encoded []byte) (model.EventEnvelope, error) {
	var wire antiflockv1.EventEnvelope
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(encoded, &wire); err != nil {
		return model.EventEnvelope{}, fmt.Errorf("decode event protobuf: %w", err)
	}
	if len(wire.ProtoReflect().GetUnknown()) != 0 {
		return model.EventEnvelope{}, errors.New("stored event contains unknown protobuf fields")
	}
	event, err := model.EventFromProto(&wire)
	if err != nil {
		return model.EventEnvelope{}, fmt.Errorf("convert stored event: %w", err)
	}
	if err := event.Validate(); err != nil {
		return model.EventEnvelope{}, fmt.Errorf("validate stored event: %w", err)
	}
	return event, nil
}
