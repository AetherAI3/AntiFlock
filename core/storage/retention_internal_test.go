package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func insertRetentionFixtureEvent(t *testing.T, database *DB, id string, sequence uint64, receivedAt time.Time) {
	t.Helper()
	_, err := database.db.ExecContext(context.Background(), `
		INSERT INTO events(
			id, schema_version, deployment_id, node_id, kind, observed_at, received_at, sequence, boot_id,
			classification, confidence, sensitivity, envelope_proto
		) VALUES (?, 'antiflock.event/v1', 'deployment', 'node', 'test.retention', ?, ?, ?, 'boot',
		          'DETECTED', 1, 'INTERNAL', ?)
	`, id, sortableTime(receivedAt), sortableTime(receivedAt), sequence, []byte{id[0]})
	if err != nil {
		t.Fatal(err)
	}
}

func prepareRetentionFixture(t *testing.T, count int) (*DB, time.Time) {
	t.Helper()
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	for index := 1; index <= count; index++ {
		insertRetentionFixtureEvent(t, database, "event-"+string(rune('a'+index-1)), uint64(index), now.Add(-48*time.Hour))
	}
	lastID := "event-" + string(rune('a'+count-1))
	if err := database.SetProjectionCursor(ctx, ProjectionCursor{
		Projection: "topology", LastEventID: lastID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return database, now
}

func TestRetentionDeletionFailureRollsBackTombstoneAndState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, now := prepareRetentionFixture(t, 1)
	if _, err := database.db.ExecContext(ctx, `
		CREATE TRIGGER reject_retention_delete BEFORE DELETE ON events
		BEGIN SELECT RAISE(ABORT, 'injected deletion failure'); END
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.PruneEvents(ctx, now.Add(-24*time.Hour), []string{"topology"}, 100); err == nil {
		t.Fatal("injected deletion failure was ignored")
	}
	var events, tombstones int
	if err := database.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_retention_tombstones`).Scan(&tombstones); err != nil {
		t.Fatal(err)
	}
	var count uint64
	var head string
	if err := database.db.QueryRowContext(ctx, `SELECT tombstone_count, head_hash FROM event_retention_state WHERE id = 1`).Scan(&count, &head); err != nil {
		t.Fatal(err)
	}
	if events != 1 || tombstones != 0 || count != 0 || head != "" {
		t.Fatalf("rollback state = events:%d tombstones:%d count:%d head:%q", events, tombstones, count, head)
	}
	if err := database.VerifyEventRetentionTombstones(ctx); err != nil {
		t.Fatalf("empty chain after rollback failed verification: %v", err)
	}
}

func TestRetentionTombstoneChainDetectsMutationAndStateRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, now := prepareRetentionFixture(t, 2)
	for range 2 {
		result, err := database.PruneEvents(ctx, now.Add(-24*time.Hour), []string{"topology"}, 1)
		if err != nil || result.Deleted != 1 || result.TombstoneHash == "" {
			t.Fatalf("retention pass = %#v, %v", result, err)
		}
	}
	if err := database.VerifyEventRetentionTombstones(ctx); err != nil {
		t.Fatalf("valid chain failed verification: %v", err)
	}
	if _, err := database.db.ExecContext(ctx, `
		UPDATE event_retention_tombstones SET batch_hash = ? WHERE id = 1
	`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := database.VerifyEventRetentionTombstones(ctx); !errors.Is(err, ErrRetentionIntegrity) {
		t.Fatalf("tombstone mutation verification error = %v", err)
	}

	database, now = prepareRetentionFixture(t, 1)
	if _, err := database.PruneEvents(ctx, now.Add(-24*time.Hour), []string{"topology"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `UPDATE event_retention_state SET tombstone_count = 0, head_hash = '' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := database.VerifyEventRetentionTombstones(ctx); !errors.Is(err, ErrRetentionIntegrity) {
		t.Fatalf("state rollback verification error = %v", err)
	}
}
