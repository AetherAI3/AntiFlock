package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	fileJournalSchema    = "antiflock.driver-journal/v1"
	fileJournalName      = "driver-journal.json"
	fileJournalLockName  = ".driver-journal.lock"
	maximumJournalBytes  = 8 << 20
	fileJournalLockDelay = 25 * time.Millisecond
)

// FileJournal is the durable Journal. It follows the same discipline as the
// enforcement plan state store: a private directory that is not reached
// through a symlink, files opened without following links, an OS lock across
// processes, write-temp-fsync-rename installs, a hard size bound, and strict
// decoding that rejects unknown fields and trailing data. Any load failure is
// ErrJournalCorrupt; the journal never repairs itself.
type FileJournal struct {
	directory string
	mu        sync.Mutex
}

type persistedJournal struct {
	SchemaVersion string                   `json:"schemaVersion"`
	Records       []persistedJournalRecord `json:"records"`
}

type persistedJournalRecord struct {
	SchemaVersion  uint32 `json:"schemaVersion"`
	Kind           string `json:"kind"`
	PlanID         string `json:"planId"`
	PlanRevision   uint64 `json:"planRevision"`
	OperationID    string `json:"operationId"`
	Step           string `json:"step"`
	OwnershipToken string `json:"ownershipToken,omitempty"`
	Digest         string `json:"digest,omitempty"`
	At             string `json:"at"`
}

// NewFileJournal creates or validates the private journal directory. The
// resolved path and its final component must not traverse a symlink.
func NewFileJournal(directory string) (*FileJournal, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("journal directory is required")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("resolve journal directory")
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, errors.New("create journal directory")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, errors.New("journal directory must not traverse symlinks")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("journal path is not a private directory")
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, errors.New("restrict journal directory")
	}
	return &FileJournal{directory: absolute}, nil
}

// Directory returns the validated journal directory.
func (journal *FileJournal) Directory() string {
	if journal == nil {
		return ""
	}
	return journal.directory
}

func (journal *FileJournal) write(ctx context.Context, record JournalRecord) error {
	if journal == nil {
		return errors.New("journal is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lock, err := journal.lock(ctx)
	if err != nil {
		return err
	}
	defer lock.close()
	state, err := journal.load()
	if err != nil {
		return err
	}
	if err := state.append(record); err != nil {
		return err
	}
	return journal.save(state)
}

// Begin implements Journal.
func (journal *FileJournal) Begin(ctx context.Context, record JournalRecord) error {
	record.Kind = JournalKindBegin
	return journal.write(ctx, record)
}

// Advance implements Journal.
func (journal *FileJournal) Advance(ctx context.Context, record JournalRecord) error {
	record.Kind = JournalKindAdvance
	return journal.write(ctx, record)
}

// Finish implements Journal.
func (journal *FileJournal) Finish(ctx context.Context, record JournalRecord) error {
	record.Kind = JournalKindFinish
	return journal.write(ctx, record)
}

func (journal *FileJournal) read(ctx context.Context) (*journalState, error) {
	if journal == nil {
		return nil, errors.New("journal is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lock, err := journal.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.close()
	return journal.load()
}

// InFlight implements Journal.
func (journal *FileJournal) InFlight(ctx context.Context) ([]JournalRecord, error) {
	state, err := journal.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.inFlight(), nil
}

// Records implements Journal.
func (journal *FileJournal) Records(ctx context.Context) ([]JournalRecord, error) {
	state, err := journal.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.records, nil
}

type journalFileLock struct {
	file *os.File
}

func (journal *FileJournal) lock(ctx context.Context) (*journalFileLock, error) {
	if err := checkPrivateDirectory(journal.directory); err != nil {
		return nil, err
	}
	file, err := openJournalLockFile(filepath.Join(journal.directory, fileJournalLockName))
	if err != nil {
		return nil, err
	}
	ticker := time.NewTicker(fileJournalLockDelay)
	defer ticker.Stop()
	for {
		acquired, err := tryLockJournalFile(file)
		if err != nil {
			file.Close()
			return nil, errors.New("acquire journal lock")
		}
		if acquired {
			return &journalFileLock{file: file}, nil
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (lock *journalFileLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := unlockJournalFile(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil || closeErr != nil {
		return errors.New("release journal lock")
	}
	return nil
}

func (journal *FileJournal) load() (*journalState, error) {
	path := filepath.Join(journal.directory, fileJournalName)
	file, err := openJournalFileNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		return &journalState{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open journal", ErrJournalCorrupt)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximumJournalBytes+1))
	if err != nil || len(content) == 0 || len(content) > maximumJournalBytes {
		return nil, fmt.Errorf("%w: journal is empty or oversized", ErrJournalCorrupt)
	}
	var persisted persistedJournal
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return nil, fmt.Errorf("%w: decode journal", ErrJournalCorrupt)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: journal contains trailing data", ErrJournalCorrupt)
	}
	if persisted.SchemaVersion != fileJournalSchema {
		return nil, fmt.Errorf("%w: journal schema is invalid", ErrJournalCorrupt)
	}
	state := &journalState{records: make([]JournalRecord, 0, len(persisted.Records))}
	for _, entry := range persisted.Records {
		record, err := entry.decode()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
		}
		state.records = append(state.records, record)
	}
	if err := state.check(); err != nil {
		return nil, err
	}
	return state, nil
}

func (journal *FileJournal) save(state *journalState) error {
	persisted := persistedJournal{SchemaVersion: fileJournalSchema, Records: make([]persistedJournalRecord, 0, len(state.records))}
	for _, record := range state.records {
		persisted.Records = append(persisted.Records, encodeJournalRecord(record))
	}
	content, err := json.Marshal(persisted)
	if err != nil || len(content) == 0 || len(content) > maximumJournalBytes {
		return errors.New("encode journal")
	}
	temporary, err := os.CreateTemp(journal.directory, ".driver-journal-*.tmp")
	if err != nil {
		return errors.New("create journal stage")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("restrict journal stage")
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("write journal stage")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync journal stage")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close journal stage")
	}
	if err := os.Rename(temporaryPath, filepath.Join(journal.directory, fileJournalName)); err != nil {
		return errors.New("install journal")
	}
	return syncJournalDirectory(journal.directory)
}

func checkPrivateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("journal directory is not a private directory")
	}
	return checkPrivateDirectoryMode(info)
}

func encodeJournalRecord(record JournalRecord) persistedJournalRecord {
	return persistedJournalRecord{
		SchemaVersion: record.SchemaVersion, Kind: record.Kind.String(),
		PlanID: record.PlanID, PlanRevision: record.PlanRevision, OperationID: record.OperationID,
		Step: record.Step.String(), OwnershipToken: record.OwnershipToken, Digest: record.Digest,
		At: record.At.UTC().Format(time.RFC3339Nano),
	}
}

func (entry persistedJournalRecord) decode() (JournalRecord, error) {
	kind, ok := journalKindByName(entry.Kind)
	if !ok {
		return JournalRecord{}, errors.New("journal record kind is unknown")
	}
	step, ok := stepByName(entry.Step)
	if !ok {
		return JournalRecord{}, errors.New("journal record step is unknown")
	}
	at, err := time.Parse(time.RFC3339Nano, entry.At)
	if err != nil {
		return JournalRecord{}, errors.New("journal record at is not RFC 3339")
	}
	record := JournalRecord{
		SchemaVersion: entry.SchemaVersion, Kind: kind,
		PlanID: entry.PlanID, PlanRevision: entry.PlanRevision, OperationID: entry.OperationID,
		Step: step, OwnershipToken: entry.OwnershipToken, Digest: entry.Digest, At: at.UTC(),
	}
	if err := record.Validate(); err != nil {
		return JournalRecord{}, err
	}
	return record, nil
}

func journalKindByName(name string) (JournalKind, bool) {
	for kind := JournalKindBegin; kind <= JournalKindFinish; kind++ {
		if kind.String() == name {
			return kind, true
		}
	}
	return JournalKindUnknown, false
}

func stepByName(name string) (Step, bool) {
	for step := StepCapture; step <= StepRollback; step++ {
		if step.String() == name {
			return step, true
		}
	}
	return StepNone, false
}
