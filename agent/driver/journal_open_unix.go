//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package driver

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openJournalFileNoFollow opens the journal read-only without following a
// final-component symlink and refuses anything but a private regular file.
func openJournalFileNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, errors.New("open journal without following links")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("bind journal descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 {
		_ = file.Close()
		return nil, errors.New("journal is not a private regular file")
	}
	return file, nil
}

// openJournalLockFile creates or opens the lock file without following links.
func openJournalLockFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open journal lock")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open journal lock")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || unix.Fchmod(descriptor, 0o600) != nil {
		_ = file.Close()
		return nil, errors.New("journal lock is not a private regular file")
	}
	return file, nil
}

func tryLockJournalFile(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return false, nil
	}
	return false, err
}

func unlockJournalFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

func syncJournalDirectory(path string) error {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open journal directory")
	}
	syncErr := unix.Fsync(descriptor)
	closeErr := unix.Close(descriptor)
	if syncErr != nil || closeErr != nil {
		return errors.New("sync journal directory")
	}
	return nil
}

func checkPrivateDirectoryMode(info os.FileInfo) error {
	if info.Mode().Perm() != 0o700 {
		return errors.New("journal directory is not private")
	}
	return nil
}
