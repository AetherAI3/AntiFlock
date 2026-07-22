package storage

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTimeHelpersAndMemoryDatabase(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Nanosecond)
	encoded := formatTime(now)
	decoded, err := parseTime(encoded)
	if err != nil || !decoded.Equal(now) {
		t.Fatalf("decoded = %v, %v", decoded, err)
	}
	if nullableTime(nil) != nil {
		t.Fatal("nil time was not stored as null")
	}
	if nullableTime(&now) != encoded {
		t.Fatalf("nullable time = %v", nullableTime(&now))
	}
	database, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenProtectsDatabaseAndRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL behavior is covered by deployment hardening rather than POSIX mode bits")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "private.db")
	database, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permission := info.Mode().Perm(); permission != 0o600 {
		t.Fatalf("database permission = %o, want 600", permission)
	}
	link := filepath.Join(directory, "linked.db")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, err := Open(context.Background(), link); err == nil {
		t.Fatal("symbolic-link database path was accepted")
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	t.Parallel()
	if _, err := Open(context.Background(), ""); err == nil {
		t.Fatal("empty database path was accepted")
	}
}
