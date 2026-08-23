// Package file is a reference ExternalWitness that records audit-head
// checkpoints in an append-only JSONL journal and signs receipts with an
// Ed25519 key held in a private key file.
//
// It is meant for a second machine or a separately-owned volume: the value of
// a witness comes from living outside the trust boundary of the node it
// witnesses. Run on the same disk as the audit database it only proves the
// journal was not edited in isolation.
//
// File discipline mirrors the rest of the repository: the key and journal
// must be regular, non-symlink files with 0600 permissions inside a 0700
// directory; the journal is only ever appended and fsynced; a torn trailing
// line left by a crash is truncated on open and never interpreted.
package file

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/DBarr3/AntiFlock/core/integration"
)

const (
	journalVersion = "antiflock.witness-journal/v1"
	maxJournalLine = 16 * 1024
	maxJournalSize = 256 << 20
)

// Config configures a file witness.
type Config struct {
	// WitnessID is the identifier placed in every receipt.
	WitnessID string
	// JournalPath is the append-only JSONL journal.
	JournalPath string
	// KeyPath holds exactly one 32-byte Ed25519 seed (see GenerateKeyFile).
	KeyPath string
	// Clock overrides the receipt clock; nil uses UTC wall time.
	Clock func() time.Time
}

// Witness is the file-backed ExternalWitness.
type Witness struct {
	id          string
	journalPath string
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	clock       func() time.Time
	mu          sync.Mutex
	last        map[string]uint64
}

type journalRecord struct {
	Version    string                 `json:"version"`
	Checkpoint integration.Checkpoint `json:"checkpoint"`
	Receipt    receiptRecord          `json:"receipt"`
}

type receiptRecord struct {
	WitnessID        string    `json:"witnessId"`
	CheckpointDigest string    `json:"checkpointDigest"`
	WitnessedAt      time.Time `json:"witnessedAt"`
	Signature        string    `json:"signature"`
	KeyID            string    `json:"keyId"`
}

// GenerateKeyFile creates a new Ed25519 seed at path with 0600 permissions.
// It refuses to overwrite an existing file and returns the public key.
func GenerateKeyFile(path string) (ed25519.PublicKey, error) {
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate witness seed: %w", err)
	}
	handle, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create witness key file: %w", err)
	}
	if _, err := handle.Write(seed); err != nil {
		handle.Close()
		return nil, fmt.Errorf("write witness key file: %w", err)
	}
	if err := handle.Sync(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("sync witness key file: %w", err)
	}
	if err := handle.Close(); err != nil {
		return nil, fmt.Errorf("close witness key file: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

// Open loads the key, replays and verifies the journal, and returns a witness
// ready to Submit.
func Open(config Config) (*Witness, error) {
	if !integration.ValidIdentifier(config.WitnessID) {
		return nil, fmt.Errorf("%w: witness id must be a canonical identifier", integration.ErrInvalidInput)
	}
	if config.JournalPath == "" || config.KeyPath == "" {
		return nil, fmt.Errorf("%w: witness journal and key paths are required", integration.ErrInvalidInput)
	}
	privateKey, err := loadPrivateKey(config.KeyPath)
	if err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	witness := &Witness{
		id: config.WitnessID, journalPath: config.JournalPath, privateKey: privateKey,
		publicKey: privateKey.Public().(ed25519.PublicKey), clock: clock, last: make(map[string]uint64),
	}
	if err := ensurePrivateDirectory(filepath.Dir(config.JournalPath)); err != nil {
		return nil, err
	}
	if err := witness.replay(); err != nil {
		return nil, err
	}
	return witness, nil
}

// PublicKey returns the receipt verification key.
func (witness *Witness) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), witness.publicKey...)
}

// Submit implements integration.ExternalWitness. A checkpoint whose sequence
// does not advance past the last recorded one for its deployment is refused
// with ErrSequenceRegression: a witness that accepted rollbacks would be
// worthless.
func (witness *Witness) Submit(ctx context.Context, checkpoint integration.Checkpoint) (integration.WitnessReceipt, error) {
	if witness == nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness is nil", integration.ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return integration.WitnessReceipt{}, err
	}
	if err := checkpoint.Validate(); err != nil {
		return integration.WitnessReceipt{}, err
	}
	digest, err := integration.CheckpointDigest(checkpoint)
	if err != nil {
		return integration.WitnessReceipt{}, err
	}
	witness.mu.Lock()
	defer witness.mu.Unlock()
	if last, seen := witness.last[checkpoint.DeploymentDigest]; seen && checkpoint.Sequence <= last {
		return integration.WitnessReceipt{}, integration.ErrSequenceRegression
	}
	receipt, err := integration.SignReceipt(integration.WitnessReceipt{
		WitnessID: witness.id, CheckpointDigest: digest, WitnessedAt: witness.clock(),
	}, witness.privateKey)
	if err != nil {
		return integration.WitnessReceipt{}, err
	}
	record := journalRecord{Version: journalVersion, Checkpoint: checkpoint, Receipt: receiptRecord{
		WitnessID: receipt.WitnessID, CheckpointDigest: receipt.CheckpointDigest, WitnessedAt: receipt.WitnessedAt,
		Signature: base64.RawURLEncoding.EncodeToString(receipt.Signature), KeyID: receipt.KeyID,
	}}
	if err := witness.appendRecord(record); err != nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: %v", integration.ErrUnavailable, err)
	}
	witness.last[checkpoint.DeploymentDigest] = checkpoint.Sequence
	return receipt, nil
}

func (witness *Witness) appendRecord(record journalRecord) error {
	content, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode witness journal record: %w", err)
	}
	if len(content) >= maxJournalLine {
		return errors.New("witness journal record is oversized")
	}
	if err := checkPrivateFile(witness.journalPath, true); err != nil {
		return err
	}
	handle, err := os.OpenFile(witness.journalPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open witness journal: %w", err)
	}
	if err := handle.Chmod(0o600); err != nil {
		handle.Close()
		return fmt.Errorf("protect witness journal: %w", err)
	}
	if _, err := handle.Write(append(content, '\n')); err != nil {
		handle.Close()
		return fmt.Errorf("append witness journal: %w", err)
	}
	if err := handle.Sync(); err != nil {
		handle.Close()
		return fmt.Errorf("sync witness journal: %w", err)
	}
	return handle.Close()
}

// replay verifies every journal line under the witness's own key and
// rebuilds the per-deployment high-water marks.
func (witness *Witness) replay() error {
	if err := checkPrivateFile(witness.journalPath, true); err != nil {
		return err
	}
	content, err := os.ReadFile(witness.journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read witness journal: %w", err)
	}
	if len(content) > maxJournalSize {
		return errors.New("witness journal is oversized")
	}
	if len(content) > 0 && content[len(content)-1] != '\n' {
		lastComplete := bytes.LastIndexByte(content, '\n')
		if err := truncateJournal(witness.journalPath, int64(lastComplete+1)); err != nil {
			return err
		}
		content = content[:lastComplete+1]
	}
	if len(content) == 0 {
		return nil
	}
	for index, line := range bytes.Split(bytes.TrimSuffix(content, []byte{'\n'}), []byte{'\n'}) {
		if len(line) >= maxJournalLine {
			return fmt.Errorf("witness journal line %d is oversized", index+1)
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var record journalRecord
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("decode witness journal line %d: %w", index+1, err)
		}
		if record.Version != journalVersion {
			return fmt.Errorf("witness journal line %d has unsupported version %q", index+1, record.Version)
		}
		signature, err := base64.RawURLEncoding.DecodeString(record.Receipt.Signature)
		if err != nil {
			return fmt.Errorf("witness journal line %d has an undecodable signature", index+1)
		}
		receipt := integration.WitnessReceipt{
			WitnessID: record.Receipt.WitnessID, CheckpointDigest: record.Receipt.CheckpointDigest,
			WitnessedAt: record.Receipt.WitnessedAt, Signature: signature, KeyID: record.Receipt.KeyID,
		}
		if err := integration.VerifyReceiptFor(receipt, record.Checkpoint, witness.publicKey); err != nil {
			return fmt.Errorf("witness journal line %d: %w", index+1, err)
		}
		if last, seen := witness.last[record.Checkpoint.DeploymentDigest]; seen && record.Checkpoint.Sequence <= last {
			return fmt.Errorf("witness journal line %d regresses a deployment sequence", index+1)
		}
		witness.last[record.Checkpoint.DeploymentDigest] = record.Checkpoint.Sequence
	}
	return nil
}

func truncateJournal(path string, length int64) error {
	handle, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open torn witness journal for repair: %w", err)
	}
	if err := handle.Truncate(length); err != nil {
		handle.Close()
		return fmt.Errorf("truncate torn witness journal tail: %w", err)
	}
	if err := handle.Sync(); err != nil {
		handle.Close()
		return fmt.Errorf("sync repaired witness journal: %w", err)
	}
	return handle.Close()
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	if err := checkPrivateFile(path, false); err != nil {
		return nil, err
	}
	seed, err := os.ReadFile(path)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: witness key file must contain one Ed25519 seed", integration.ErrInvalidInput)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// checkPrivateFile enforces the repository's key-file discipline: a regular,
// non-symlink file with 0600 permissions. allowMissing permits a journal that
// has not been created yet.
func checkPrivateFile(path string, allowMissing bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: witness file %s is not accessible", integration.ErrInvalidInput, filepath.Base(path))
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: witness file %s must be a regular non-symlink file", integration.ErrInvalidInput, filepath.Base(path))
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: witness file %s must have 0600 permissions", integration.ErrInvalidInput, filepath.Base(path))
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create witness directory: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve witness directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return fmt.Errorf("%w: witness directory must not traverse symlinks", integration.ErrInvalidInput)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("restrict witness directory: %w", err)
		}
	}
	return nil
}

// Factory is a Registry factory. Options: "witness-id", "journal", "key".
func Factory(_ context.Context, options integration.Options) (any, error) {
	return Open(Config{WitnessID: options["witness-id"], JournalPath: options["journal"], KeyPath: options["key"]})
}

var _ integration.ExternalWitness = (*Witness)(nil)
