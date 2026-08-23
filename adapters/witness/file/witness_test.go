package file_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/adapters/witness/file"
	"github.com/DBarr3/AntiFlock/core/integration"
	"github.com/DBarr3/AntiFlock/core/integration/conformance"
)

func newConfig(t *testing.T) file.Config {
	t.Helper()
	dir := t.TempDir()
	config := file.Config{WitnessID: "file-witness", JournalPath: filepath.Join(dir, "witness.jsonl"), KeyPath: filepath.Join(dir, "witness.key")}
	if _, err := file.GenerateKeyFile(config.KeyPath); err != nil {
		t.Fatal(err)
	}
	return config
}

func checkpoint(sequence uint64) integration.Checkpoint {
	return integration.Checkpoint{
		DeploymentDigest: integration.DigestString("deployment"), AuditHeadDigest: integration.DigestString("head"),
		Sequence: sequence, IssuedAt: time.Date(2026, 8, 23, 12, 0, int(sequence), 0, time.UTC),
	}
}

func TestFileWitnessConformance(t *testing.T) {
	t.Parallel()
	conformance.RunExternalWitness(t, func(t *testing.T) (integration.ExternalWitness, ed25519.PublicKey) {
		witness, err := file.Open(newConfig(t))
		if err != nil {
			t.Fatal(err)
		}
		return witness, witness.PublicKey()
	})
}

func TestFileWitnessReplaysJournalAndRefusesRollback(t *testing.T) {
	t.Parallel()
	config := newConfig(t)
	witness, err := file.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		if _, err := witness.Submit(context.Background(), checkpoint(sequence)); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := file.Open(config)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := reopened.Submit(context.Background(), checkpoint(3)); !errors.Is(err, integration.ErrSequenceRegression) {
		t.Fatalf("rollback after reopen = %v, want ErrSequenceRegression", err)
	}
	receipt, err := reopened.Submit(context.Background(), checkpoint(4))
	if err != nil {
		t.Fatal(err)
	}
	if err := integration.VerifyReceiptFor(receipt, checkpoint(4), reopened.PublicKey()); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(config.JournalPath)
	if strings.Count(string(content), "\n") != 4 {
		t.Fatalf("journal has %d lines, want 4", strings.Count(string(content), "\n"))
	}
	if strings.Contains(string(content), "deployment\"") {
		t.Fatal("journal carries a raw identifier")
	}
}

func TestFileWitnessDetectsJournalTampering(t *testing.T) {
	t.Parallel()
	config := newConfig(t)
	witness, err := file.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Submit(context.Background(), checkpoint(9)); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(config.JournalPath)
	tampered := strings.Replace(string(content), `"sequence":9`, `"sequence":8`, 1)
	if tampered == string(content) {
		t.Fatal("fixture did not find the sequence to tamper")
	}
	if err := os.WriteFile(config.JournalPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Open(config); err == nil || !errors.Is(err, integration.ErrInvalidReceipt) {
		t.Fatalf("tampered journal opened: %v", err)
	}
	// A torn trailing line from a crash is repaired, not interpreted.
	if err := os.WriteFile(config.JournalPath, append(content, []byte(`{"version":"antiflock.witness-journal/v1","checkpoint":{"sequence":99`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	repaired, err := file.Open(config)
	if err != nil {
		t.Fatalf("torn journal not repaired: %v", err)
	}
	if _, err := repaired.Submit(context.Background(), checkpoint(10)); err != nil {
		t.Fatalf("append after repair: %v", err)
	}
	after, _ := os.ReadFile(config.JournalPath)
	if strings.Count(string(after), "\n") != 2 || strings.Contains(string(after), `"sequence":99`) {
		t.Fatalf("journal after repair: %q", after)
	}
}

func TestFileWitnessKeyFileDiscipline(t *testing.T) {
	t.Parallel()
	config := newConfig(t)
	if _, err := file.GenerateKeyFile(config.KeyPath); err == nil {
		t.Fatal("GenerateKeyFile overwrote an existing key")
	}
	linked := config
	linked.KeyPath = filepath.Join(t.TempDir(), "link.key")
	if err := os.Symlink(config.KeyPath, linked.KeyPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := file.Open(linked); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("symlinked key accepted: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(config.KeyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Open(config); !errors.Is(err, integration.ErrInvalidInput) {
			t.Fatalf("world-readable key accepted: %v", err)
		}
		_ = os.Chmod(config.KeyPath, 0o600)
	}
	short := config
	short.KeyPath = filepath.Join(t.TempDir(), "short.key")
	if err := os.WriteFile(short.KeyPath, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Open(short); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("short seed accepted: %v", err)
	}
	if _, err := file.Open(file.Config{WitnessID: "bad id", JournalPath: config.JournalPath, KeyPath: config.KeyPath}); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("non-canonical witness id accepted: %v", err)
	}
}

func TestFileWitnessRegistryFactory(t *testing.T) {
	t.Parallel()
	config := newConfig(t)
	registry := integration.NewRegistry()
	if err := registry.Register("file", integration.KindExternalWitness, file.Factory); err != nil {
		t.Fatal(err)
	}
	witness, err := registry.NewExternalWitness(context.Background(), "file", integration.Options{
		"witness-id": config.WitnessID, "journal": config.JournalPath, "key": config.KeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Submit(context.Background(), checkpoint(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.NewExternalWitness(context.Background(), "file", nil); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("factory without paths = %v, want ErrInvalidInput", err)
	}
}
