//go:build !windows

package sim

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type liveStateLock struct {
	file *os.File
}

func acquireLiveStateLock(ctx context.Context, directory string) (*liveStateLock, error) {
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, ".lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open simulator state lock")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("open simulator state lock")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || unix.Fchmod(fd, 0o600) != nil {
		file.Close()
		return nil, errors.New("restrict simulator state lock")
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return &liveStateLock{file: file}, nil
		} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
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
	err := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
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
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open simulator state directory")
	}
	syncErr := unix.Fsync(fd)
	closeErr := unix.Close(fd)
	if syncErr != nil || closeErr != nil {
		return errors.New("sync simulator state directory")
	}
	return nil
}
