package driver_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
)

func record(step driver.Step, at time.Time) driver.JournalRecord {
	return driver.JournalRecord{
		SchemaVersion: driver.ContractVersion, PlanID: "plan", PlanRevision: 1, OperationID: "op", Step: step, At: at,
	}
}

func journalSuite(t *testing.T, open func(t *testing.T) driver.Journal) {
	t.Helper()
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	t.Run("begin advance finish", func(t *testing.T) {
		journal := open(t)
		if err := journal.Begin(ctx, record(driver.StepCapture, at)); err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := journal.Begin(ctx, record(driver.StepCapture, at)); !errors.Is(err, driver.ErrJournalActive) {
			t.Fatalf("duplicate begin: err = %v, want ErrJournalActive", err)
		}
		if err := journal.Advance(ctx, record(driver.StepCapture, at)); !errors.Is(err, driver.ErrJournalOrder) {
			t.Fatalf("advance to same step: err = %v, want ErrJournalOrder", err)
		}
		if err := journal.Advance(ctx, record(driver.StepApply, at)); err != nil {
			t.Fatalf("advance: %v", err)
		}
		if err := journal.Advance(ctx, record(driver.StepSimulate, at)); !errors.Is(err, driver.ErrJournalOrder) {
			t.Fatalf("advance backwards: err = %v, want ErrJournalOrder", err)
		}
		inFlight, err := journal.InFlight(ctx)
		if err != nil || len(inFlight) != 1 || inFlight[0].Step != driver.StepApply {
			t.Fatalf("in-flight = %+v (%v), want one APPLY", inFlight, err)
		}
		if err := journal.Finish(ctx, record(driver.StepApply, at)); !errors.Is(err, driver.ErrInvalidRequest) {
			t.Fatalf("finish at non-terminal step: err = %v, want ErrInvalidRequest", err)
		}
		if err := journal.Finish(ctx, record(driver.StepCommit, at)); err != nil {
			t.Fatalf("finish: %v", err)
		}
		if err := journal.Finish(ctx, record(driver.StepCommit, at)); !errors.Is(err, driver.ErrJournalInactive) {
			t.Fatalf("double finish: err = %v, want ErrJournalInactive", err)
		}
		inFlight, err = journal.InFlight(ctx)
		if err != nil || len(inFlight) != 0 {
			t.Fatalf("in-flight after finish = %+v (%v), want none", inFlight, err)
		}
		records, err := journal.Records(ctx)
		if err != nil || len(records) != 3 {
			t.Fatalf("records = %d (%v), want 3", len(records), err)
		}
	})

	t.Run("advance without begin", func(t *testing.T) {
		journal := open(t)
		if err := journal.Advance(ctx, record(driver.StepApply, at)); !errors.Is(err, driver.ErrJournalInactive) {
			t.Fatalf("err = %v, want ErrJournalInactive", err)
		}
	})

	t.Run("invalid record", func(t *testing.T) {
		journal := open(t)
		bad := record(driver.StepCapture, at)
		bad.PlanID = ""
		if err := journal.Begin(ctx, bad); !errors.Is(err, driver.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
		bad = record(driver.StepCapture, at)
		bad.Digest = "not-hex"
		if err := journal.Begin(ctx, bad); !errors.Is(err, driver.ErrInvalidRequest) {
			t.Fatalf("bad digest: err = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("expired context", func(t *testing.T) {
		journal := open(t)
		expired, cancel := context.WithDeadline(ctx, time.Unix(0, 0))
		defer cancel()
		if err := journal.Begin(expired, record(driver.StepCapture, at)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want DeadlineExceeded", err)
		}
	})
}

func TestMemoryJournal(t *testing.T) {
	t.Parallel()
	journalSuite(t, func(t *testing.T) driver.Journal { return driver.NewMemoryJournal() })
	t.Run("corrupt", func(t *testing.T) {
		journal := driver.NewMemoryJournal()
		journal.Corrupt()
		if _, err := journal.InFlight(context.Background()); !errors.Is(err, driver.ErrJournalCorrupt) {
			t.Fatalf("err = %v, want ErrJournalCorrupt", err)
		}
	})
}

func TestFileJournal(t *testing.T) {
	t.Parallel()
	journalSuite(t, func(t *testing.T) driver.Journal {
		journal, err := driver.NewFileJournal(t.TempDir())
		if err != nil {
			t.Fatalf("file journal: %v", err)
		}
		return journal
	})
}

func TestFileJournalSurvivesReopen(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	first, err := driver.NewFileJournal(directory)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entry := record(driver.StepApply, at)
	entry.OwnershipToken = strings.Repeat("a", 64)
	entry.Digest = strings.Repeat("b", 64)
	if err := first.Begin(context.Background(), entry); err != nil {
		t.Fatalf("begin: %v", err)
	}
	second, err := driver.NewFileJournal(directory)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	entry.Kind = driver.JournalKindBegin
	inFlight, err := second.InFlight(context.Background())
	if err != nil || len(inFlight) != 1 || inFlight[0] != entry {
		t.Fatalf("in-flight after reopen = %+v (%v), want %+v", inFlight, err, entry)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(directory, "driver-journal.json"))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("journal file mode = %v (%v), want 0600", info.Mode(), err)
		}
	}
}

func TestFileJournalRejectsCorruption(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown field":   `{"schemaVersion":"antiflock.driver-journal/v1","records":[],"extra":1}`,
		"wrong schema":    `{"schemaVersion":"antiflock.driver-journal/v2","records":[]}`,
		"trailing data":   `{"schemaVersion":"antiflock.driver-journal/v1","records":[]} {}`,
		"not json":        `garbage`,
		"empty":           ``,
		"unknown kind":    `{"schemaVersion":"antiflock.driver-journal/v1","records":[{"schemaVersion":1,"kind":"WHATEVER","planId":"p","planRevision":1,"operationId":"o","step":"APPLY","at":"2026-08-23T12:00:00Z"}]}`,
		"unknown step":    `{"schemaVersion":"antiflock.driver-journal/v1","records":[{"schemaVersion":1,"kind":"BEGIN","planId":"p","planRevision":1,"operationId":"o","step":"EXPLODE","at":"2026-08-23T12:00:00Z"}]}`,
		"finish no begin": `{"schemaVersion":"antiflock.driver-journal/v1","records":[{"schemaVersion":1,"kind":"FINISH","planId":"p","planRevision":1,"operationId":"o","step":"COMMIT","at":"2026-08-23T12:00:00Z"}]}`,
		"double begin":    `{"schemaVersion":"antiflock.driver-journal/v1","records":[{"schemaVersion":1,"kind":"BEGIN","planId":"p","planRevision":1,"operationId":"o","step":"APPLY","at":"2026-08-23T12:00:00Z"},{"schemaVersion":1,"kind":"BEGIN","planId":"p","planRevision":1,"operationId":"o","step":"APPLY","at":"2026-08-23T12:00:00Z"}]}`,
		"bad time":        `{"schemaVersion":"antiflock.driver-journal/v1","records":[{"schemaVersion":1,"kind":"BEGIN","planId":"p","planRevision":1,"operationId":"o","step":"APPLY","at":"yesterday"}]}`,
		"record schema":   `{"schemaVersion":"antiflock.driver-journal/v1","records":[{"schemaVersion":2,"kind":"BEGIN","planId":"p","planRevision":1,"operationId":"o","step":"APPLY","at":"2026-08-23T12:00:00Z"}]}`,
		"control char id": `{"schemaVersion":"antiflock.driver-journal/v1","records":[{"schemaVersion":1,"kind":"BEGIN","planId":"p\u001b","planRevision":1,"operationId":"o","step":"APPLY","at":"2026-08-23T12:00:00Z"}]}`,
	}
	for name, content := range cases {
		content := content
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			journal, err := driver.NewFileJournal(directory)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if err := os.WriteFile(filepath.Join(directory, "driver-journal.json"), []byte(content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := journal.InFlight(context.Background()); !errors.Is(err, driver.ErrJournalCorrupt) {
				t.Fatalf("in-flight: err = %v, want ErrJournalCorrupt", err)
			}
			if err := journal.Begin(context.Background(), record(driver.StepCapture, time.Unix(1, 0))); !errors.Is(err, driver.ErrJournalCorrupt) {
				t.Fatalf("begin over corrupt journal: err = %v, want ErrJournalCorrupt", err)
			}
			if content, err := os.ReadFile(filepath.Join(directory, "driver-journal.json")); err != nil || string(content) != cases[name] {
				t.Fatal("journal repaired or rewrote a corrupt file")
			}
		})
	}
}

func TestFileJournalRejectsOversizedFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	journal, err := driver.NewFileJournal(directory)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	padding := strings.Repeat(" ", 8<<20)
	if err := os.WriteFile(filepath.Join(directory, "driver-journal.json"), []byte(`{"schemaVersion":"antiflock.driver-journal/v1","records":[]}`+padding), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := journal.InFlight(context.Background()); !errors.Is(err, driver.ErrJournalCorrupt) {
		t.Fatalf("err = %v, want ErrJournalCorrupt", err)
	}
}

func TestFileJournalRejectsSymlinks(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privilege on windows")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := driver.NewFileJournal(link); err == nil {
		t.Fatal("journal accepted a symlinked directory")
	}
	directory := filepath.Join(base, "journal")
	journal, err := driver.NewFileJournal(directory)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	elsewhere := filepath.Join(base, "elsewhere.json")
	if err := os.WriteFile(elsewhere, []byte(`{"schemaVersion":"antiflock.driver-journal/v1","records":[]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(directory, "driver-journal.json")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := journal.InFlight(context.Background()); !errors.Is(err, driver.ErrJournalCorrupt) {
		t.Fatalf("symlinked journal file: err = %v, want ErrJournalCorrupt", err)
	}
}

func TestFileJournalRequiresDirectory(t *testing.T) {
	t.Parallel()
	if _, err := driver.NewFileJournal(""); err == nil {
		t.Fatal("empty directory accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := driver.NewFileJournal(file); err == nil {
		t.Fatal("regular file accepted as journal directory")
	}
}

func TestFileJournalBlocksConcurrentWriters(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	first, err := driver.NewFileJournal(directory)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	second, err := driver.NewFileJournal(directory)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	done := make(chan error, 2)
	for i, journal := range []driver.Journal{first, second} {
		i := i
		journal := journal
		go func() {
			entry := record(driver.StepCapture, at)
			entry.OperationID = "op-" + string(rune('a'+i))
			done <- journal.Begin(context.Background(), entry)
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent begin: %v", err)
		}
	}
	records, err := first.Records(context.Background())
	if err != nil || len(records) != 2 {
		t.Fatalf("records = %d (%v), want both writers preserved", len(records), err)
	}
}
