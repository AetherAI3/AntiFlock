//go:build linux

package enforcement

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	fileStateSchema       = "antiflock.plan-state/v1"
	fileStateName         = "plan-state.json"
	fileStateLockName     = ".plan-state.lock"
	maximumFileStateBytes = 8 << 20
)

// FileStateStore is the Linux durable replay boundary for plan execution. It
// uses an OS lock across processes and atomically persists every reservation
// before any driver mutation. An interrupted in-progress reservation remains
// fail-closed and requires operator recovery; it is never silently retried.
type FileStateStore struct {
	directory string
}

type persistedFileState struct {
	SchemaVersion      string                         `json:"schemaVersion"`
	LastPolicyRevision uint64                         `json:"lastPolicyRevision"`
	LastPlanRevision   uint64                         `json:"lastPlanRevision"`
	Records            map[string]persistedFileRecord `json:"records"`
}

type persistedFileRecord struct {
	Reservation Reservation `json:"reservation"`
	Result      []byte      `json:"result,omitempty"`
}

// NewFileStateStore creates or validates a private Linux state directory.
// The resolved path and its final component must not traverse a symlink.
func NewFileStateStore(directory string) (*FileStateStore, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("plan state directory is required")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("resolve plan state directory")
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, errors.New("create plan state directory")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, errors.New("plan state directory must not traverse symlinks")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("plan state path is not a private directory")
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, errors.New("restrict plan state directory")
	}
	return &FileStateStore{directory: absolute}, nil
}

func (store *FileStateStore) Reserve(ctx context.Context, reservation Reservation) (*antiflockv1.PlanExecutionResult, error) {
	if store == nil {
		return nil, errors.New("plan state store is required")
	}
	if err := validateReservation(reservation); err != nil {
		return nil, ErrPlanReplay
	}
	lock, err := store.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.close()
	state, err := store.load()
	if err != nil {
		return nil, err
	}
	if existing, ok := state.Records[reservation.PlanID]; ok {
		if existing.Reservation != reservation {
			return nil, ErrPlanReplay
		}
		if len(existing.Result) == 0 {
			return nil, ErrPlanInProgress
		}
		var result antiflockv1.PlanExecutionResult
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(existing.Result, &result); err != nil || model.RejectUnknownFields(&result) != nil {
			return nil, errors.New("persisted plan result is invalid")
		}
		return &result, nil
	}
	if reservation.PolicyRevision < state.LastPolicyRevision || reservation.PlanRevision <= state.LastPlanRevision {
		return nil, ErrPlanReplay
	}
	state.LastPolicyRevision = reservation.PolicyRevision
	state.LastPlanRevision = reservation.PlanRevision
	state.Records[reservation.PlanID] = persistedFileRecord{Reservation: reservation}
	if err := store.save(state); err != nil {
		return nil, err
	}
	return nil, nil
}

func (store *FileStateStore) Complete(ctx context.Context, result *antiflockv1.PlanExecutionResult) error {
	if store == nil || result == nil || result.GetPlanId() == "" || result.GetPlanRevision() == 0 {
		return errors.New("terminal plan result is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := model.RejectUnknownFields(result); err != nil {
		return errors.New("terminal plan result contains unknown fields")
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		return errors.New("encode terminal plan result")
	}
	lock, err := store.lock(ctx)
	if err != nil {
		return err
	}
	defer lock.close()
	state, err := store.load()
	if err != nil {
		return err
	}
	record, ok := state.Records[result.GetPlanId()]
	if !ok || record.Reservation.PlanRevision != result.GetPlanRevision() {
		return errors.New("plan result has no matching reservation")
	}
	if len(record.Result) != 0 {
		if bytes.Equal(record.Result, canonical) {
			return nil
		}
		return ErrPlanReplay
	}
	record.Result = canonical
	state.Records[result.GetPlanId()] = record
	return store.save(state)
}

// Revisions reads the durable monotonic revision floor under the OS lock.
func (store *FileStateStore) Revisions(ctx context.Context) (uint64, uint64, error) {
	if store == nil {
		return 0, 0, errors.New("plan state store is required")
	}
	lock, err := store.lock(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer lock.close()
	state, err := store.load()
	if err != nil {
		return 0, 0, err
	}
	return state.LastPolicyRevision, state.LastPlanRevision, nil
}

func validateReservation(reservation Reservation) error {
	if reservation.PlanID == "" || len(reservation.PlanID) > 128 || strings.TrimSpace(reservation.PlanID) != reservation.PlanID ||
		reservation.Fingerprint == "" || len(reservation.Fingerprint) > 256 || strings.TrimSpace(reservation.Fingerprint) != reservation.Fingerprint ||
		reservation.PolicyRevision == 0 || reservation.PlanRevision == 0 {
		return errors.New("plan reservation is invalid")
	}
	return nil
}

type planFileLock struct {
	file *os.File
}

func (store *FileStateStore) lock(ctx context.Context) (*planFileLock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directoryFD, err := unix.Open(store.directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open plan state directory")
	}
	var directoryStat unix.Stat_t
	validDirectory := unix.Fstat(directoryFD, &directoryStat) == nil && directoryStat.Mode&unix.S_IFMT == unix.S_IFDIR && directoryStat.Mode&0o777 == 0o700
	_ = unix.Close(directoryFD)
	if !validDirectory {
		return nil, errors.New("plan state directory is not private")
	}
	path := filepath.Join(store.directory, fileStateLockName)
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open plan state lock")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("open plan state lock")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || unix.Fchmod(fd, 0o600) != nil {
		file.Close()
		return nil, errors.New("plan state lock is not a private regular file")
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return &planFileLock{file: file}, nil
		} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			file.Close()
			return nil, errors.New("acquire plan state lock")
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (lock *planFileLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil || closeErr != nil {
		return errors.New("release plan state lock")
	}
	return nil
}

func (store *FileStateStore) load() (*persistedFileState, error) {
	path := filepath.Join(store.directory, fileStateName)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return &persistedFileState{SchemaVersion: fileStateSchema, Records: make(map[string]persistedFileRecord)}, nil
	}
	if err != nil {
		return nil, errors.New("open plan state")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("open plan state")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 {
		return nil, errors.New("plan state is not a private regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumFileStateBytes+1))
	if err != nil || len(content) == 0 || len(content) > maximumFileStateBytes {
		return nil, errors.New("read plan state")
	}
	var state persistedFileState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, errors.New("decode plan state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("plan state contains trailing data")
	}
	if state.SchemaVersion != fileStateSchema || state.Records == nil {
		return nil, errors.New("plan state schema is invalid")
	}
	for id, record := range state.Records {
		if id != record.Reservation.PlanID || validateReservation(record.Reservation) != nil || len(record.Result) > maximumFileStateBytes {
			return nil, errors.New("plan state record is invalid")
		}
		if len(record.Result) != 0 {
			var result antiflockv1.PlanExecutionResult
			if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(record.Result, &result); err != nil ||
				model.RejectUnknownFields(&result) != nil || result.GetPlanId() != record.Reservation.PlanID ||
				result.GetPlanRevision() != record.Reservation.PlanRevision {
				return nil, errors.New("persisted plan result does not match its reservation")
			}
		}
	}
	return &state, nil
}

func (store *FileStateStore) save(state *persistedFileState) error {
	if state == nil || state.SchemaVersion != fileStateSchema || state.Records == nil {
		return errors.New("plan state is invalid")
	}
	content, err := json.Marshal(state)
	if err != nil || len(content) == 0 || len(content) > maximumFileStateBytes {
		return errors.New("encode plan state")
	}
	temporary, err := os.CreateTemp(store.directory, ".plan-state-*.tmp")
	if err != nil {
		return errors.New("create plan state stage")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("restrict plan state stage")
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("write plan state stage")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync plan state stage")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close plan state stage")
	}
	if err := os.Rename(temporaryPath, filepath.Join(store.directory, fileStateName)); err != nil {
		return errors.New("install plan state")
	}
	directoryFD, err := unix.Open(store.directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open plan state directory")
	}
	syncErr := unix.Fsync(directoryFD)
	closeErr := unix.Close(directoryFD)
	if syncErr != nil || closeErr != nil {
		return errors.New("sync plan state directory")
	}
	return nil
}
