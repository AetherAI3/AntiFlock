//go:build windows

package sim

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

type liveStateLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireLiveStateLock(ctx context.Context, directory string) (*liveStateLock, error) {
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(directory, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("open simulator state lock")
	}
	lock := &liveStateLock{file: file}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			file.Close()
			return nil, errors.New("acquire simulator state lock")
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (lock *liveStateLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return errors.New("release simulator state lock")
	}
	if closeErr != nil {
		return errors.New("close simulator state lock")
	}
	return nil
}

func syncLiveStateDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return errors.New("open simulator state directory")
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("sync simulator state directory")
	}
	return nil
}
