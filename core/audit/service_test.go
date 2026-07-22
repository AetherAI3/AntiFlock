package audit_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/storage"
)

func TestAppendCreatesVerifiableHashChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := audit.New(database, privateKey, filepath.Join(t.TempDir(), "audit-anchor.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Append(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: "operator_one", Action: "policy.created",
		ResourceType: "policy", ResourceID: "policy_one", Outcome: "success",
		Details: map[string]any{"revision": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Append(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: "operator_one", Action: "policy.activated",
		ResourceType: "policy", ResourceID: "policy_one", Outcome: "success",
		Details: map[string]any{"revision": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.PreviousHash != first.EntryHash {
		t.Fatalf("second previous hash = %q, want %q", second.PreviousHash, first.EntryHash)
	}
	if err := service.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := database.ListAuditEntries(ctx, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %d, %v", len(entries), err)
	}
}

func TestVerifyWalksEveryAuditPage(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := audit.New(database, privateKey, filepath.Join(directory, "audit-anchor.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 235; index++ {
		if _, err := service.Append(ctx, audit.AppendRequest{
			ActorType: "test", ActorID: "pagination", Action: "test.appended",
			ResourceType: "entry", ResourceID: "same", Outcome: "success",
			Details: map[string]any{"index": index},
		}); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
	if err := service.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	head, err := database.GetAuditHead(ctx)
	if err != nil || head.Count != 235 {
		t.Fatalf("head = %#v, %v", head, err)
	}
}

func TestExternalAnchorDetectsCoherentDatabaseTruncation(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "audit.db")
	database, err := storage.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := audit.New(database, privateKey, filepath.Join(directory, "audit-anchor.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Append(ctx, audit.AppendRequest{ActorType: "test", ActorID: "one", Action: "one", ResourceType: "test", ResourceID: "one", Outcome: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(ctx, audit.AppendRequest{ActorType: "test", ActorID: "two", Action: "two", ResourceType: "test", ResourceID: "two", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	attacker, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	if _, err := attacker.ExecContext(ctx, `DELETE FROM audit_entries WHERE sequence > 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := attacker.ExecContext(ctx, `UPDATE audit_state SET entry_count = 1, sequence = 1, head_hash = ? WHERE id = 1`, first.EntryHash); err != nil {
		t.Fatal(err)
	}
	if err := service.Verify(ctx); err == nil {
		t.Fatal("coherent database truncation was not detected by the external anchor")
	}
}

func TestIndependentAuditServicesCannotForkTheHead(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(directory, "audit-anchor.jsonl")
	first, err := audit.New(database, privateKey, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := audit.New(database, privateKey, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for index, service := range []*audit.Service{first, second} {
		wait.Add(1)
		go func(index int, service *audit.Service) {
			defer wait.Done()
			<-start
			_, err := service.Append(ctx, audit.AppendRequest{
				ActorType: "test", ActorID: "concurrent", Action: "concurrent.append",
				ResourceType: "entry", ResourceID: string(rune('a' + index)), Outcome: "success",
			})
			results <- err
		}(index, service)
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded := 0
	for result := range results {
		if result == nil {
			succeeded++
		}
	}
	if succeeded != 2 {
		t.Fatalf("successful serialized concurrent appends = %d, want both", succeeded)
	}
	if err := first.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	head, err := database.GetAuditHead(ctx)
	if err != nil || head.Count != 2 {
		t.Fatalf("head after concurrent append = %#v, %v", head, err)
	}
}

func TestConcurrentFirstBootWritesExactlyOneGenesisAnchor(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(directory, "audit-anchor.jsonl")
	const callers = 16
	start := make(chan struct{})
	errorsByCaller := make(chan error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, createErr := audit.New(database, privateKey, anchorPath)
			errorsByCaller <- createErr
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByCaller)
	for createErr := range errorsByCaller {
		if createErr != nil {
			t.Fatal(createErr)
		}
	}
	content, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("anchor genesis records = %d, want one", len(lines))
	}
}

func TestStaleLockFileContentsDoNotBlockAuditStartupOrGetOverwritten(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(directory, "audit-anchor.jsonl")
	lockPath := anchorPath + ".lock"
	const staleContents = "metadata left by a process that exited without cleanup"
	if err := os.WriteFile(lockPath, []byte(staleContents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.New(database, privateKey, anchorPath); err != nil {
		t.Fatalf("start audit service with stale lock-file contents: %v", err)
	}
	content, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != staleContents {
		t.Fatal("kernel lock acquisition overwrote stale lock-file contents")
	}
}

func TestVerifyRepairsEveryDatabaseAheadAnchorStep(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(directory, "audit-anchor.jsonl")
	service, err := audit.New(database, privateKey, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if _, err := service.Append(ctx, audit.AppendRequest{
			ActorType: "test", ActorID: "recovery", Action: "audit.recovery",
			ResourceType: "entry", ResourceID: fmt.Sprintf("entry_%d", index), Outcome: "success",
		}); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	genesis := strings.SplitN(string(content), "\n", 2)[0] + "\n"
	if err := os.WriteFile(anchorPath, []byte(genesis), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.Verify(ctx); err != nil {
		t.Fatalf("repair database-ahead anchor: %v", err)
	}
	if err := service.Verify(ctx); err != nil {
		t.Fatalf("verify repaired anchor: %v", err)
	}
	repaired, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(repaired)), "\n"); len(lines) != 4 {
		t.Fatalf("repaired anchor records = %d, want genesis plus three entries", len(lines))
	}
}

func TestVerifyRepairsTornLastAnchorAndReplaysCommittedTail(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(directory, "audit-anchor.jsonl")
	service, err := audit.New(database, privateKey, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if _, err := service.Append(ctx, audit.AppendRequest{
			ActorType: "test", ActorID: "torn-tail", Action: "audit.appended",
			ResourceType: "entry", ResourceID: fmt.Sprintf("entry_%d", index), Outcome: "success",
		}); err != nil {
			t.Fatal(err)
		}
	}
	complete, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	withoutFinalNewline := bytes.TrimSuffix(complete, []byte{'\n'})
	lastRecordStart := bytes.LastIndexByte(withoutFinalNewline, '\n') + 1
	lastRecordLength := len(withoutFinalNewline) - lastRecordStart
	if lastRecordStart <= 0 || lastRecordLength < 2 {
		t.Fatal("test anchor journal does not contain a final record to tear")
	}
	torn := append([]byte(nil), withoutFinalNewline[:lastRecordStart+lastRecordLength/2]...)
	if err := os.WriteFile(anchorPath, torn, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := service.Verify(ctx); err != nil {
		t.Fatalf("recover torn committed anchor tail: %v", err)
	}
	if err := service.Verify(ctx); err != nil {
		t.Fatalf("verify after torn-tail recovery: %v", err)
	}
	repaired, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(repaired) == 0 || repaired[len(repaired)-1] != '\n' {
		t.Fatal("repaired anchor journal is not newline-terminated")
	}
	if lines := bytes.Split(bytes.TrimSuffix(repaired, []byte{'\n'}), []byte{'\n'}); len(lines) != 4 {
		t.Fatalf("repaired anchor records = %d, want genesis plus three entries", len(lines))
	}
	head, err := database.GetAuditHead(ctx)
	if err != nil || head.Count != 3 {
		t.Fatalf("audit head after torn-tail recovery = %#v, %v", head, err)
	}
}

func TestHistoricalKeyringVerifiesAuditChainAcrossSigningKeyRotation(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(directory, "audit-anchor.jsonl")
	oldService, err := audit.New(database, oldPrivate, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	oldEntry, err := oldService.Append(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: "rotation", Action: "audit.before_rotation",
		ResourceType: "key", ResourceID: "old", Outcome: "success",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	callerOwnedPrivate := append(ed25519.PrivateKey(nil), newPrivate...)
	rotated, err := audit.NewWithKeyring(database, callerOwnedPrivate, []ed25519.PublicKey{oldPublic}, anchorPath)
	if err != nil {
		t.Fatalf("initialize rotated audit signer with historical key: %v", err)
	}
	// Service construction must not retain a caller-mutable private-key slice.
	for index := range callerOwnedPrivate {
		callerOwnedPrivate[index] = 0
	}
	newEntry, err := rotated.Append(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: "rotation", Action: "audit.after_rotation",
		ResourceType: "key", ResourceID: "new", Outcome: "success",
	})
	if err != nil {
		t.Fatal(err)
	}
	if oldEntry.KeyID == newEntry.KeyID {
		t.Fatal("audit signing key ID did not change after rotation")
	}
	if err := rotated.Verify(ctx); err != nil {
		t.Fatalf("verify mixed-key audit chain: %v", err)
	}
	restarted, err := audit.NewWithKeyring(database, newPrivate, []ed25519.PublicKey{oldPublic}, anchorPath)
	if err != nil {
		t.Fatalf("restart rotated verifier with historical key: %v", err)
	}
	if err := restarted.Verify(ctx); err != nil {
		t.Fatalf("verify mixed-key audit chain after restart: %v", err)
	}
	if _, err := audit.New(database, newPrivate, anchorPath); err == nil || !strings.Contains(err.Error(), "unknown audit anchor signing key") {
		t.Fatalf("rotated verifier without historical key error = %v", err)
	}
}

func TestAppendRejectsIncompleteEntryAndNilMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := audit.New(database, privateKey, filepath.Join(t.TempDir(), "audit-anchor.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(ctx, audit.AppendRequest{}); err == nil {
		t.Fatal("incomplete entry was accepted")
	}
	if _, err := service.AppendWithMutation(ctx, audit.AppendRequest{}, nil); err == nil {
		t.Fatal("nil mutation was accepted")
	}
}
