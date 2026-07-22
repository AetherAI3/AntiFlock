package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type DB struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	if path != ":memory:" {
		directory := filepath.Dir(path)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
		if err := protectStorageDirectory(directory); err != nil {
			return nil, fmt.Errorf("protect database directory: %w", err)
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("database path must not be a symbolic link")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect database path: %w", err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create private database file: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close private database file: %w", err)
		}
		if err := protectStorageFile(path); err != nil {
			return nil, fmt.Errorf("protect database file: %w", err)
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	database.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = FULL",
		"PRAGMA secure_delete = ON",
		"PRAGMA trusted_schema = OFF",
		"PRAGMA temp_store = MEMORY",
	} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			database.Close()
			return nil, fmt.Errorf("configure sqlite: %w", err)
		}
	}
	if path != ":memory:" {
		if _, err := database.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
			database.Close()
			return nil, fmt.Errorf("enable sqlite WAL: %w", err)
		}
	}

	result := &DB{db: database}
	if err := result.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return result, nil
}

func (database *DB) Close() error {
	return database.db.Close()
}

func (database *DB) Health(ctx context.Context) error {
	var value int
	if err := database.db.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil {
		return fmt.Errorf("sqlite health check: %w", err)
	}
	if value != 1 {
		return errors.New("sqlite health check returned unexpected value")
	}
	return nil
}

func (database *DB) migrate(ctx context.Context) error {
	if _, err := database.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		var exists int
		err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", entry.Name()).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", entry.Name(), err)
		}
		if exists > 0 {
			continue
		}
		content, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		tx, err := database.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", entry.Name(), formatTime(time.Now().UTC())); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

func sortableTime(value time.Time) int64 {
	if value.IsZero() {
		return math.MinInt64
	}
	return value.UTC().UnixNano()
}

func parseSortableTime(value int64) time.Time {
	return time.Unix(0, value).UTC()
}
